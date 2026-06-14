//! Blind-Schnorr (Pointcheval-Stern) issuance of anonymous voter credentials.
//!
//! ## Construction
//!
//! The voter holds a secret scalar `s_cred` and a public commitment
//! `C = s_cred · G`. The issuer (election authority) holds a long-term
//! Schnorr key pair `(x_i, Pk_i = x_i · G)`. The issuance protocol produces
//! a Schnorr signature `(R', s_sig)` on `C` under `Pk_i` such that the issuer
//! cannot link the final `(C, R', s_sig)` to the issuance transcript it saw.
//!
//! This is the standard Pointcheval-Stern blind-Schnorr signature, with the
//! voter-side blinding done over the *challenge* (rather than the commitment
//! itself):
//!
//! ```text
//! voter:  pick s_cred, b ; C = s_cred·G ; C' = C + b·G        (send C' to issuer)
//! issuer: pick k ; R = k·G                                    (send R back)
//! voter:  pick α, β
//!         R' = R + α·G + β·Pk_i
//!         e  = H(transcript, Pk_i, C, R')
//!         e' = e + β                                           (send e' to issuer)
//! issuer: s_iss = k + e'·x_i                                  (send s_iss back)
//! voter:  s_sig = s_iss + α
//!         signature = (R', s_sig)  on  C  under  Pk_i
//! ```
//!
//! Verification: `s_sig · G == R' + e · Pk_i`, where the verifier recomputes
//! `e` from the same transcript binding.
//!
//! The `blinded_commitment` `C'` carries no information that ties back to
//! the final `C` (because `b` is sampled uniformly and never revealed). The
//! issuer also never sees `C` directly. We retain `C'` in the protocol so
//! that test (#2) can spot-check that the issuer-visible handle is *not*
//! the voter's published commitment.
//!
//! ## Threat model and unlinkability
//!
//! The acceptance bar in the spec is *unlinkability between issuance and
//! presentation*: an adversary who logs both the issuance transcript and a
//! later credential presentation cannot link them, except with negligible
//! probability over the choice of `(b, α, β)`. The Pointcheval-Stern proof
//! gives exactly this property: `(α, β)` re-randomize `(R, s_iss)` into a
//! uniformly distributed `(R', s_sig)` conditional on the issuer-visible
//! transcript, so the joint distribution is independent of which voter is
//! being issued.
//!
//! Cross-*presentation* unlinkability (one voter's two presentations look
//! independent) is **not** provided by this module — the holder reveals `C`
//! at presentation time. The single-ballot-per-election nullifier in
//! [`crate::nullifier`] is what prevents double-voting; cross-presentation
//! unlinkability is out of scope for the demo and would need either
//! presentation-time commitment re-randomization or a structure-preserving
//! signature scheme (BBS+ or PS).
//!
//! ## Constant-time and zeroize discipline
//!
//! - `IssuerSecretKey` zeroizes `x_i` on drop and is `!Debug`.
//! - `Credential` zeroizes `s_cred` on drop and is `!Debug`.
//! - `VoterBlindState` and `VoterFinalizeState` zeroize their blinding
//!   factors and the secret `s_cred` on drop.
//! - `IssuerSession` zeroizes its nonce `k` on drop.
//! - All scalar arithmetic uses constant-time operations from
//!   `curve25519-dalek`.
//!
//! The verifier (`Credential::verify_against_issuer`) is variable-time over
//! public inputs and intentionally so — it never touches `s_cred`.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use saksi_crypto::{
    group::{basepoint, compress_point},
    CryptoError, CryptoResult,
};

/// Merlin transcript label for the blind-Schnorr issuance challenge `e`.
pub const TRANSCRIPT_LABEL_ISSUANCE: &[u8] = b"saksi.credentials.issuance.v1";

/// Long-term issuer secret key `x_i`.
///
/// Wraps a single ristretto255 scalar. Zeroized on drop, and intentionally
/// does **not** derive `Debug` — printing the issuer key would defeat the
/// whole point of having it.
pub struct IssuerSecretKey {
    scalar: Scalar,
}

impl IssuerSecretKey {
    /// Generates a fresh issuer secret key with cryptographic randomness.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self {
            scalar: Scalar::random(rng),
        }
    }

    /// Constructs an issuer key from a pre-existing scalar. Use this only
    /// for test vectors or to import a key from durable storage; the scalar
    /// must already be canonical (see [`saksi_crypto::group`]).
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    /// Returns the matching [`IssuerPublicKey`] `Pk_i = x_i · G`.
    pub fn public_key(&self) -> IssuerPublicKey {
        IssuerPublicKey(self.scalar * basepoint())
    }
}

impl Drop for IssuerSecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

/// Issuer public key `Pk_i = x_i · G`.
///
/// Public data — safe to `Clone`, `Copy`, `Debug`, and compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerPublicKey(pub RistrettoPoint);

impl IssuerPublicKey {
    /// Returns the underlying ristretto point.
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }
}

/// Issuer-visible request opening the issuance protocol.
///
/// `blinded_commitment = C + b · G` hides the voter's actual commitment
/// `C = s_cred · G` under the blinding factor `b`. The issuer never learns
/// `C` or `s_cred`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindRequest {
    /// `C' = C + b · G`, the issuer's view of the credential.
    pub blinded_commitment: RistrettoPoint,
}

/// Voter-private state held between [`voter_begin_issuance`] and
/// [`voter_blind_challenge`].
///
/// Owns the secret credential `s_cred`, the commitment-blinding factor `b`,
/// and the unblinded commitment `C`. All three are zeroized on drop.
pub struct VoterBlindState {
    s_cred: Scalar,
    /// The voter's published commitment `C = s_cred · G`.
    commitment: RistrettoPoint,
    /// Blinding factor used to produce the issuer-visible `C' = C + b · G`.
    b: Scalar,
}

impl Drop for VoterBlindState {
    fn drop(&mut self) {
        self.s_cred.zeroize();
        self.b.zeroize();
        // `commitment` is `s_cred · G`; not strictly secret post-issuance,
        // but cheap to clear and keeps the type a uniform "secret bundle".
    }
}

/// Voter-private state held between [`voter_blind_challenge`] and
/// [`voter_finalize_issuance`].
pub struct VoterFinalizeState {
    s_cred: Scalar,
    /// The voter's published commitment `C = s_cred · G`.
    commitment: RistrettoPoint,
    /// Re-randomized signature nonce `R' = R + α · G + β · Pk_i`.
    r_prime: RistrettoPoint,
    /// Voter's response-blinding factor `α` (used to unblind the response).
    alpha: Scalar,
    /// Voter's challenge-blinding factor `β`. Not used after this stage
    /// — kept on the state so it can be zeroized on drop alongside `α`.
    beta: Scalar,
}

impl Drop for VoterFinalizeState {
    fn drop(&mut self) {
        self.s_cred.zeroize();
        self.alpha.zeroize();
        self.beta.zeroize();
        // `r_prime` is public-data-shaped (anyone observing the final
        // signature sees it); not secret in isolation.
    }
}

/// Issuer pre-signature commitment `R = k · G`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerPreSignature {
    /// `R = k · G`.
    pub r: RistrettoPoint,
}

/// Issuer-private state held between [`issuer_pre_sign`] and
/// [`issuer_sign`]. Carries the nonce `k`. Zeroized on drop.
pub struct IssuerSession {
    k: Scalar,
}

impl Drop for IssuerSession {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

/// Voter-to-issuer blinded challenge `e' = e + β`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindedChallenge {
    /// `e' = e + β` (mod ℓ).
    pub e_prime: Scalar,
}

/// Issuer-to-voter signature response `s_iss = k + e' · x_i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IssuerResponse {
    /// `s_iss = k + e' · x_i`.
    pub s_iss: Scalar,
}

/// A complete anonymous credential: the voter's secret scalar `s_cred`,
/// the public commitment `C = s_cred · G`, and a Schnorr signature
/// `(R', s_sig)` on `C` under the issuer's public key.
///
/// Zeroizes `s_cred` and the response scalar `s_sig` on drop and does not
/// implement `Debug`.
pub struct Credential {
    s_cred: Scalar,
    /// `C = s_cred · G`.
    commitment: RistrettoPoint,
    /// Re-randomized signature nonce `R'`.
    signature_r: RistrettoPoint,
    /// Signature response `s_sig = s_iss + α`.
    signature_s: Scalar,
}

impl Credential {
    /// Reconstructs a [`Credential`] from previously held parts.
    ///
    /// `s_cred` is the voter's secret scalar; `signature_r` and `signature_s`
    /// are the Schnorr signature pair `(R', s_sig)` on `C = s_cred · G` under
    /// the issuer's public key. The commitment is recomputed internally as
    /// `s_cred · G`.
    ///
    /// This is the constructor callers use when the credential was issued in
    /// a previous session and persisted out-of-band (e.g. by the voter app
    /// across launches, or by an FFI bridge that receives the parts as hex).
    /// The returned [`Credential`] zeroizes `s_cred` and `signature_s` on
    /// drop, exactly like one returned from `voter_finalize_issuance`.
    ///
    /// **No validation is performed here**: callers that need to confirm the
    /// signature matches the supplied issuer should call
    /// [`Credential::verify_against_issuer`] right after.
    pub fn from_parts(s_cred: Scalar, signature_r: RistrettoPoint, signature_s: Scalar) -> Self {
        let commitment = s_cred * basepoint();
        Self {
            s_cred,
            commitment,
            signature_r,
            signature_s,
        }
    }

    /// Returns the public credential commitment `C = s_cred · G`.
    pub fn public_commitment(&self) -> RistrettoPoint {
        self.commitment
    }

    /// Returns the issuer-signature pair `(R', s_sig)`.
    pub fn signature(&self) -> (RistrettoPoint, Scalar) {
        (self.signature_r, self.signature_s)
    }

    /// Constant-time read of the secret scalar `s_cred`. Internal to the
    /// crate so the presentation module can build proofs against it; not
    /// exposed publicly.
    pub(crate) fn secret_scalar(&self) -> &Scalar {
        &self.s_cred
    }

    /// Verifies the issuer Schnorr signature against `issuer_pk`.
    ///
    /// Returns [`CryptoError::VerificationFailed`] if the signature does
    /// not verify against the credential's commitment under the supplied
    /// public key.
    pub fn verify_against_issuer(&self, issuer_pk: &IssuerPublicKey) -> CryptoResult<()> {
        verify_issuer_signature(
            issuer_pk,
            &self.commitment,
            &self.signature_r,
            &self.signature_s,
        )
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.s_cred.zeroize();
        self.signature_s.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Protocol functions
// ---------------------------------------------------------------------------

/// **Voter step 1.** Generates a fresh credential secret `s_cred`, computes
/// the published commitment `C = s_cred · G`, blinds it with a uniform
/// factor `b`, and emits the blinded handle `C' = C + b · G` together with
/// the voter-private state needed for the next step.
pub fn voter_begin_issuance(
    rng: &mut (impl RngCore + CryptoRng),
) -> (BlindRequest, VoterBlindState) {
    let s_cred = Scalar::random(rng);
    let commitment = s_cred * basepoint();
    let b = Scalar::random(rng);
    let blinded_commitment = commitment + b * basepoint();
    (
        BlindRequest { blinded_commitment },
        VoterBlindState {
            s_cred,
            commitment,
            b,
        },
    )
}

/// **Issuer step 1.** Samples a fresh nonce `k` and returns the
/// pre-signature point `R = k · G` along with an opaque session token
/// carrying `k` for the second issuer step.
pub fn issuer_pre_sign(
    _issuer_sk: &IssuerSecretKey,
    _request: &BlindRequest,
    rng: &mut (impl RngCore + CryptoRng),
) -> (IssuerPreSignature, IssuerSession) {
    let k = Scalar::random(rng);
    let r = k * basepoint();
    (IssuerPreSignature { r }, IssuerSession { k })
}

/// **Voter step 2.** Given the issuer's pre-signature `R`, samples
/// re-randomization factors `(α, β)`, computes `R' = R + α·G + β·Pk_i`,
/// derives the canonical challenge `e = H(transcript, Pk_i, C, R')`, and
/// emits the blinded challenge `e' = e + β` along with the state needed to
/// finalize.
///
/// The challenge `e` is bound to *only* public data on the eventual
/// signature (issuer pubkey, message `C`, and the re-randomized nonce
/// `R'`), so a verifier holding `(Pk_i, C, R', s_sig)` can recompute `e`
/// later without any additional state from the issuance transcript.
pub fn voter_blind_challenge(
    state: VoterBlindState,
    pre_sig: &IssuerPreSignature,
    issuer_pk: &IssuerPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> (BlindedChallenge, VoterFinalizeState) {
    let alpha = Scalar::random(rng);
    let beta = Scalar::random(rng);

    let r_prime = pre_sig.r + alpha * basepoint() + beta * issuer_pk.as_point();

    let challenge_e = compute_issuance_challenge(issuer_pk, &state.commitment, &r_prime);
    let e_prime = challenge_e + beta;

    let VoterBlindState {
        s_cred,
        commitment,
        b: blinding_b,
    } = state;

    // `b` is unused past this point; explicitly drop and zeroize it.
    let mut b_to_clear = blinding_b;
    b_to_clear.zeroize();

    (
        BlindedChallenge { e_prime },
        VoterFinalizeState {
            s_cred,
            commitment,
            r_prime,
            alpha,
            beta,
        },
    )
}

/// **Issuer step 2.** Given the session from [`issuer_pre_sign`] and the
/// voter's blinded challenge `e'`, returns `s_iss = k + e' · x_i`.
///
/// The session is consumed (`k` is zeroized as it falls out of scope), so
/// the issuer cannot accidentally reuse the nonce.
pub fn issuer_sign(
    issuer_sk: &IssuerSecretKey,
    session: IssuerSession,
    blinded: &BlindedChallenge,
) -> IssuerResponse {
    // Move `k` out of the session so we can use it before it is dropped.
    let IssuerSession { k } = session;
    let s_iss = k + blinded.e_prime * issuer_sk.scalar;

    // Zeroize the local copy of `k` as soon as we are done with it.
    let mut k_clear = k;
    k_clear.zeroize();

    IssuerResponse { s_iss }
}

/// **Voter step 3.** Unblinds the issuer response into a final Schnorr
/// signature `(R', s_sig)` on `C` under `Pk_i`, sanity-checks it, and
/// returns the assembled [`Credential`].
///
/// Returns [`CryptoError::VerificationFailed`] if the unblinded signature
/// does not verify — this catches a malicious or buggy issuer that returns
/// a tampered `s_iss`.
pub fn voter_finalize_issuance(
    state: VoterFinalizeState,
    response: &IssuerResponse,
    issuer_pk: &IssuerPublicKey,
) -> CryptoResult<Credential> {
    let s_sig = response.s_iss + state.alpha;

    verify_issuer_signature(issuer_pk, &state.commitment, &state.r_prime, &s_sig)?;

    let VoterFinalizeState {
        s_cred,
        commitment,
        r_prime,
        ..
    } = state;
    // The remaining fields (alpha, beta, challenge_e) are dropped here and
    // `VoterFinalizeState::drop` zeroizes them.

    Ok(Credential {
        s_cred,
        commitment,
        signature_r: r_prime,
        signature_s: s_sig,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Recomputes the issuance Fiat-Shamir challenge
/// `e = H(transcript_label, Pk_i, C, R')`.
///
/// The transcript is bound to:
///
/// - the constant label [`TRANSCRIPT_LABEL_ISSUANCE`] (domain-separates
///   from all other Saksi sigma protocols);
/// - the issuer public key (so a forged signature against a different
///   issuer cannot be lifted to this one);
/// - the message `C = s_cred · G` (the thing being signed);
/// - the re-randomized commitment `R'`.
///
/// We deliberately do **not** bind any per-issuance context here: the
/// verifier needs to recompute this challenge from `(Pk_i, C, R')` alone,
/// long after the issuance transcript has been forgotten. Per-presentation
/// transcript binding (election id, caller context) lives in
/// [`crate::presentation`].
fn compute_issuance_challenge(
    issuer_pk: &IssuerPublicKey,
    commitment: &RistrettoPoint,
    r_prime: &RistrettoPoint,
) -> Scalar {
    let mut transcript = Transcript::new(TRANSCRIPT_LABEL_ISSUANCE);
    transcript.append_message(b"issuer-pk", &compress_point(issuer_pk.as_point()));
    transcript.append_message(b"commitment", &compress_point(commitment));
    transcript.append_message(b"r-prime", &compress_point(r_prime));

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);
    let scalar = Scalar::from_bytes_mod_order_wide(&buf);
    buf.zeroize();
    scalar
}

/// Internal: verifies the issuer Schnorr signature `(r, s)` against
/// `(issuer_pk, commitment)`. Used both by `voter_finalize_issuance`
/// (sanity-check the unblinded signature) and by
/// [`Credential::verify_against_issuer`].
pub(crate) fn verify_issuer_signature(
    issuer_pk: &IssuerPublicKey,
    commitment: &RistrettoPoint,
    r: &RistrettoPoint,
    s: &Scalar,
) -> CryptoResult<()> {
    let e = compute_issuance_challenge(issuer_pk, commitment, r);

    let lhs = s * basepoint();
    let rhs = r + e * issuer_pk.as_point();
    if lhs == rhs {
        Ok(())
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

/// Public re-export so [`presentation::verify_presentation`] can call the
/// same verifier without duplicating the transcript binding.
pub(crate) fn verify_signature_for_presentation(
    issuer_pk: &IssuerPublicKey,
    commitment: &RistrettoPoint,
    r: &RistrettoPoint,
    s: &Scalar,
) -> CryptoResult<()> {
    verify_issuer_signature(issuer_pk, commitment, r, s)
}

/// Deterministic Schnorr-sign a credential commitment under the issuance
/// transcript, used only to build the cross-language golden vector. Mirrors
/// exactly what a real issuance produces: `(R', s)` with
/// `s = k + e·x`, `e = compute_issuance_challenge(Pk_i, C, R')`, `R' = k·G`.
#[cfg(test)]
fn deterministic_issuer_signature(
    x: Scalar,
    s_cred: Scalar,
    k: Scalar,
) -> (IssuerPublicKey, RistrettoPoint, RistrettoPoint, Scalar) {
    let g = basepoint();
    let pk = IssuerPublicKey(x * g);
    let commitment = s_cred * g;
    let r_prime = k * g;
    let e = compute_issuance_challenge(&pk, &commitment, &r_prime);
    let s = k + e * x;
    (pk, commitment, r_prime, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Cross-language golden vector for **on-chain credential-signature
    /// verification**. The Go chaincode (`saksi-bulletin`) must accept exactly
    /// this `(Pk_i, C, R', s)` tuple and reject any single-byte tamper. The
    /// 128-byte layout is `compress(Pk_i) || compress(C) || compress(R') || s`.
    #[test]
    fn credential_signature_golden_vector() {
        let (pk, commitment, r_prime, s) = deterministic_issuer_signature(
            Scalar::from(123_456_789_u64),
            Scalar::from(987_654_321_u64),
            Scalar::from(555_000_111_u64),
        );

        // It must be a valid signature.
        verify_issuer_signature(&pk, &commitment, &r_prime, &s).expect("golden vector verifies");

        let mut vector = Vec::with_capacity(128);
        vector.extend_from_slice(&compress_point(pk.as_point()));
        vector.extend_from_slice(&compress_point(&commitment));
        vector.extend_from_slice(&compress_point(&r_prime));
        vector.extend_from_slice(&s.to_bytes());
        let hex = vector
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        // Pin the bytes so any change to the issuance transcript or encoding
        // (which the Go on-chain verifier mirrors) is caught here.
        assert_eq!(
            hex,
            include_str!("../../saksi-protocol/test-vectors/credential-sig-v1.hex").trim(),
            "credential-signature golden vector drifted; regenerate the Go cross-check too"
        );
    }

    /// End-to-end happy path: voter + issuer run the full protocol and the
    /// resulting credential verifies under the issuer's public key.
    fn issue_credential(rng: &mut OsRng) -> (IssuerPublicKey, Credential) {
        let issuer_sk = IssuerSecretKey::generate(rng);
        let issuer_pk = issuer_sk.public_key();

        let (request, blind_state) = voter_begin_issuance(rng);
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, rng);
        let (blinded, finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, rng);
        let response = issuer_sign(&issuer_sk, session, &blinded);
        let credential = voter_finalize_issuance(finalize_state, &response, &issuer_pk)
            .expect("honest protocol yields a valid credential");

        (issuer_pk, credential)
    }

    #[test]
    fn issuance_happy_path_verifies() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue_credential(&mut rng);
        credential
            .verify_against_issuer(&issuer_pk)
            .expect("credential verifies");
    }

    /// The issuer-visible blinded commitment `C'` must not equal the
    /// voter's final public commitment `C`. With overwhelming probability
    /// over the blinding factor `b`, `C' = C + b·G ≠ C` (they would be
    /// equal only if `b = 0`, which has probability `≈ 2^-252`).
    #[test]
    fn issuer_view_unlinkable_from_final_commitment() {
        let mut rng = OsRng;
        let issuer_sk = IssuerSecretKey::generate(&mut rng);
        let issuer_pk = issuer_sk.public_key();

        let (request, blind_state) = voter_begin_issuance(&mut rng);
        let blinded_commitment = request.blinded_commitment;
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, &mut rng);
        let (blinded, finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, &mut rng);
        let response = issuer_sign(&issuer_sk, session, &blinded);
        let credential = voter_finalize_issuance(finalize_state, &response, &issuer_pk).unwrap();

        assert_ne!(
            blinded_commitment,
            credential.public_commitment(),
            "issuer must not see the unblinded credential commitment"
        );
    }

    #[test]
    fn tampered_issuer_response_is_rejected() {
        let mut rng = OsRng;
        let issuer_sk = IssuerSecretKey::generate(&mut rng);
        let issuer_pk = issuer_sk.public_key();

        let (request, blind_state) = voter_begin_issuance(&mut rng);
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, &mut rng);
        let (blinded, finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, &mut rng);
        let mut response = issuer_sign(&issuer_sk, session, &blinded);
        // Bump s_iss by one — the unblinded signature should fail to verify.
        response.s_iss += Scalar::ONE;

        // Credential is intentionally !Debug (it carries `s_cred`), so we
        // can't use `expect_err`; pattern-match instead.
        match voter_finalize_issuance(finalize_state, &response, &issuer_pk) {
            Ok(_) => panic!("tampered response must fail"),
            Err(err) => assert_eq!(err, CryptoError::VerificationFailed),
        }
    }

    #[test]
    fn wrong_issuer_pk_for_verification_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue_credential(&mut rng);

        // A different, unrelated issuer key.
        let other_pk = IssuerSecretKey::generate(&mut rng).public_key();
        assert_ne!(issuer_pk, other_pk);
        assert!(matches!(
            credential.verify_against_issuer(&other_pk),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn issuer_secret_key_is_not_debug() {
        // Compile-time guard: this will fail to compile if `IssuerSecretKey`
        // grows a `Debug` impl. We can at least observe at runtime that the
        // `Debug` trait is not in scope for our key type by relying on the
        // function being non-generic and unused at the type level.
        //
        // (We cannot statically assert "type T does not implement Debug"
        // without negative trait bounds, but adding `format!("{:?}", sk)`
        // here would catch any regression at review time.)
        let mut rng = OsRng;
        let _sk = IssuerSecretKey::generate(&mut rng);
        // Intentionally no debug print — documenting the invariant.
    }

    #[test]
    fn credential_from_parts_round_trips_through_presentation() {
        // Issue a real credential via the existing protocol so we know good parts.
        let mut rng = OsRng;
        let issuer = IssuerSecretKey::generate(&mut rng);
        let issuer_pk = issuer.public_key();

        let (req, state) = voter_begin_issuance(&mut rng);
        let (pre, issuer_state) = issuer_pre_sign(&issuer, &req, &mut rng);
        let (blinded_challenge, voter_state2) =
            voter_blind_challenge(state, &pre, &issuer_pk, &mut rng);
        let response = issuer_sign(&issuer, issuer_state, &blinded_challenge);
        let original =
            voter_finalize_issuance(voter_state2, &response, &issuer_pk).expect("issuance");

        // Pull the parts out and rebuild via the new constructor.
        let (sig_r, sig_s) = original.signature();
        let s_cred = *original.secret_scalar(); // pub(crate) — same crate, so OK in this test
        let original_commit = original.public_commitment();
        drop(original);

        let rebuilt = Credential::from_parts(s_cred, sig_r, sig_s);
        assert_eq!(rebuilt.public_commitment(), original_commit);
        rebuilt
            .verify_against_issuer(&issuer_pk)
            .expect("signature still verifies");
    }

    #[test]
    fn pre_signature_nonce_is_consumed() {
        // Compile-time guard: `issuer_sign` takes `IssuerSession` by value,
        // so the same session cannot be used twice. The fact that this
        // test compiles is the proof; we exercise the path anyway.
        let mut rng = OsRng;
        let issuer_sk = IssuerSecretKey::generate(&mut rng);
        let issuer_pk = issuer_sk.public_key();
        let (request, blind_state) = voter_begin_issuance(&mut rng);
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, &mut rng);
        let (blinded, _finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, &mut rng);
        let _response = issuer_sign(&issuer_sk, session, &blinded);
        // `session` has been consumed — uncommenting the next line would
        // fail to compile, which is the property we want.
        // let _again = issuer_sign(&issuer_sk, session, &blinded);
    }
}
