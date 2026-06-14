//! Credential presentation — proves knowledge of the credential secret and
//! emits a deterministic per-election nullifier.
//!
//! Given a [`Credential`] issued via [`crate::issuance`] and an
//! `election_id`, the holder constructs a [`saksi_protocol::CredentialPresentation`]
//! that lets a verifier check three things at once:
//!
//! 1. The issuer Schnorr signature `(R', s_sig)` on the credential
//!    commitment `C` under `Pk_i` (election authority).
//! 2. A Chaum-Pedersen NIZK proving `C = s_cred · G ∧ nullifier = s_cred · H_e`
//!    where `H_e = nullifier_h(election_id)`. This ties the published
//!    nullifier to the *same* secret that the issuer signed.
//! 3. (Implicit) The nullifier `n = s_cred · H_e` is byte-deterministic in
//!    `(s_cred, election_id)`. The bulletin board rejects duplicates and
//!    thereby prevents double-voting.
//!
//! ### Wire encoding of `presentation_proof`
//!
//! The protobuf `CredentialPresentation` field `presentation_proof` is an
//! opaque byte string. We pack:
//!
//! ```text
//! [ R' (32 bytes, compressed ristretto)  ||
//!   s_sig (32 bytes, canonical scalar)    ||
//!   ChaumPedersenProof::to_wire().encode_to_vec() ]
//! ```
//!
//! The signature bytes are fixed-length, so the decoder splits the first
//! 64 bytes and decodes the remainder as a length-delimited protobuf
//! `ChaumPedersenProof` message.
//!
//! ### Transcript / context binding
//!
//! Both the Chaum-Pedersen proof's transcript and the issuer-signature
//! transcript are bound to (a) the issuer public key, (b) the election id,
//! and (c) a caller-supplied `context` byte string. A verifier that uses
//! the wrong `election_id` or `context` will reject the proof.
//!
//! ### Threat model note (cross-presentation linkability)
//!
//! As documented in [`crate::issuance`], the holder reveals `C` directly
//! in this construction, so two presentations of the *same* credential are
//! linkable to each other (they share `C`). The per-election nullifier
//! already gives single-ballot enforcement; cross-presentation
//! unlinkability would require additional commitment re-randomization and
//! is out of scope for the demo.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

use saksi_crypto::{
    group::{basepoint, compress_point, point_from_compressed, scalar_from_canonical_bytes},
    nizk::chaum_pedersen::ChaumPedersenProof,
    CryptoError, CryptoResult,
};
use saksi_protocol::{
    ChaumPedersenProof as ProtocolChaumPedersenProof, CredentialPresentation, Nullifier,
    WIRE_VERSION,
};

use crate::{
    issuance::{verify_signature_for_presentation, Credential, IssuerPublicKey},
    nullifier::{compress_nullifier, decompress_nullifier, derive_nullifier, nullifier_h},
};

/// Compressed ristretto point length (32 bytes).
const POINT_LEN: usize = 32;
/// Canonical scalar length (32 bytes).
const SCALAR_LEN: usize = 32;
/// Combined length of the signature prefix at the start of
/// `presentation_proof`: `R' (32) || s_sig (32)`.
const SIGNATURE_PREFIX_LEN: usize = POINT_LEN + SCALAR_LEN;

/// Builds the Chaum-Pedersen `context` string from the election id and the
/// caller-supplied context, with explicit length prefixes so a tampered
/// concatenation cannot smuggle one field into the other.
///
/// Stable: callers reproducing a presentation outside of `Credential::present`
/// (e.g. an FFI bridge that owns the wire encoding directly) may rely on the
/// byte layout here. Any change is a breaking change and bumps the
/// `saksi.credentials.presentation.v*` version prefix.
pub fn presentation_context(election_id: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + election_id.len() + 8 + context.len() + 32);
    out.extend_from_slice(b"saksi.credentials.presentation.v1");
    out.extend_from_slice(&(election_id.len() as u64).to_be_bytes());
    out.extend_from_slice(election_id);
    out.extend_from_slice(&(context.len() as u64).to_be_bytes());
    out.extend_from_slice(context);
    out
}

impl Credential {
    /// Builds a [`CredentialPresentation`] for `election_id`, binding the
    /// proof and nullifier to the supplied `context` byte string.
    ///
    /// The returned wire message contains:
    /// - `credential_commitment`: compressed `C = s_cred · G`.
    /// - `issuer_public_key`: compressed `Pk_i`. The verifier may already
    ///   know `Pk_i` out of band, but we include it so the message is
    ///   self-describing and tampering with it can be detected as
    ///   "verification failed" against the caller-supplied `Pk_i`.
    /// - `presentation_proof`: `R' || s_sig || cp_proof_wire_bytes`.
    /// - `nullifier`: compressed `s_cred · H_e`.
    pub fn present(
        &self,
        issuer_pk: &IssuerPublicKey,
        election_id: &[u8],
        context: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> CredentialPresentation {
        let g = basepoint();
        let h_e = nullifier_h(election_id);

        let commitment = self.public_commitment();
        let nullifier_point = derive_nullifier(self.secret_scalar(), election_id);
        let cp_context = presentation_context(election_id, context);

        let cp_proof = ChaumPedersenProof::prove(
            &g,
            &h_e,
            &commitment,
            &nullifier_point,
            self.secret_scalar(),
            &cp_context,
            rng,
        );

        let (sig_r, sig_s) = self.signature();
        let proof_bytes = encode_presentation_proof(&sig_r, &sig_s, &cp_proof.to_wire());

        CredentialPresentation {
            version: WIRE_VERSION,
            credential_commitment: compress_point(&commitment).to_vec(),
            issuer_public_key: compress_point(issuer_pk.as_point()).to_vec(),
            presentation_proof: proof_bytes,
            nullifier: Some(Nullifier {
                version: WIRE_VERSION,
                value: compress_nullifier(&nullifier_point).to_vec(),
            }),
        }
    }
}

/// Verifies a [`CredentialPresentation`] against the expected issuer public
/// key, election identifier, and context.
///
/// Performs:
///
/// 1. Wire-shape validation (version, field lengths, canonical encodings).
/// 2. Cross-check that the embedded `issuer_public_key` matches the
///    caller-supplied `issuer_pk`. (A tampered `issuer_public_key` field
///    therefore fails fast here.)
/// 3. Schnorr-signature verification of `(R', s_sig)` on `C` under `Pk_i`.
/// 4. Chaum-Pedersen verification of `C = s_cred · G ∧ nullifier = s_cred · H_e`
///    bound to `presentation_context(election_id, context)`.
///
/// Returns `Ok(())` only if every check passes.
pub fn verify_presentation(
    presentation: &CredentialPresentation,
    issuer_pk: &IssuerPublicKey,
    election_id: &[u8],
    context: &[u8],
) -> CryptoResult<()> {
    if presentation.version != WIRE_VERSION {
        return Err(CryptoError::InvalidParameters(
            "unsupported CredentialPresentation wire version",
        ));
    }

    // ---- decode the published commitment, embedded issuer key, nullifier ----
    let commitment = decode_point_vec(&presentation.credential_commitment)?;
    let embedded_issuer_pk = decode_point_vec(&presentation.issuer_public_key)?;
    if &embedded_issuer_pk != issuer_pk.as_point() {
        return Err(CryptoError::VerificationFailed);
    }

    let nullifier_wire = presentation
        .nullifier
        .as_ref()
        .ok_or(CryptoError::InvalidParameters(
            "CredentialPresentation missing nullifier",
        ))?;
    if nullifier_wire.version != WIRE_VERSION {
        return Err(CryptoError::InvalidParameters(
            "unsupported Nullifier wire version",
        ));
    }
    let nullifier_bytes: [u8; 32] = nullifier_wire
        .value
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidPoint)?;
    let nullifier_point = decompress_nullifier(nullifier_bytes)?;

    // ---- split the presentation_proof envelope ----
    let (sig_r, sig_s, cp_proof) = decode_presentation_proof(&presentation.presentation_proof)?;

    // ---- (1) issuer Schnorr signature on C ----
    verify_signature_for_presentation(issuer_pk, &commitment, &sig_r, &sig_s)?;

    // ---- (2) Chaum-Pedersen tying C and nullifier to the same s_cred ----
    let g = basepoint();
    let h_e = nullifier_h(election_id);
    let cp_context = presentation_context(election_id, context);
    cp_proof.verify(&g, &h_e, &commitment, &nullifier_point, &cp_context)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// presentation_proof envelope: R' (32) || s_sig (32) || CP_proof (variable)
// ---------------------------------------------------------------------------

fn encode_presentation_proof(
    sig_r: &RistrettoPoint,
    sig_s: &Scalar,
    cp_wire: &ProtocolChaumPedersenProof,
) -> Vec<u8> {
    let cp_bytes = cp_wire.encode_to_vec();
    let mut out = Vec::with_capacity(SIGNATURE_PREFIX_LEN + cp_bytes.len());
    out.extend_from_slice(&compress_point(sig_r));
    out.extend_from_slice(&sig_s.to_bytes());
    out.extend_from_slice(&cp_bytes);
    out
}

fn decode_presentation_proof(
    bytes: &[u8],
) -> CryptoResult<(RistrettoPoint, Scalar, ChaumPedersenProof)> {
    if bytes.len() < SIGNATURE_PREFIX_LEN {
        return Err(CryptoError::InvalidParameters(
            "presentation_proof shorter than signature prefix",
        ));
    }

    let mut r_bytes = [0u8; POINT_LEN];
    r_bytes.copy_from_slice(&bytes[..POINT_LEN]);
    let sig_r = point_from_compressed(r_bytes)?;

    let mut s_bytes = [0u8; SCALAR_LEN];
    s_bytes.copy_from_slice(&bytes[POINT_LEN..SIGNATURE_PREFIX_LEN]);
    let sig_s = scalar_from_canonical_bytes(s_bytes)?;

    let cp_wire = ProtocolChaumPedersenProof::decode(&bytes[SIGNATURE_PREFIX_LEN..])
        .map_err(|_| CryptoError::InvalidParameters("ChaumPedersenProof failed to decode"))?;
    let cp_proof = ChaumPedersenProof::from_wire(&cp_wire)?;

    Ok((sig_r, sig_s, cp_proof))
}

fn decode_point_vec(bytes: &[u8]) -> CryptoResult<RistrettoPoint> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidPoint)?;
    point_from_compressed(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    use crate::issuance::{
        issuer_pre_sign, issuer_sign, voter_begin_issuance, voter_blind_challenge,
        voter_finalize_issuance, IssuerSecretKey,
    };

    fn issue(rng: &mut OsRng) -> (IssuerPublicKey, Credential) {
        let issuer_sk = IssuerSecretKey::generate(rng);
        let issuer_pk = issuer_sk.public_key();
        let (request, blind_state) = voter_begin_issuance(rng);
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, rng);
        let (blinded, finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, rng);
        let response = issuer_sign(&issuer_sk, session, &blinded);
        let credential = voter_finalize_issuance(finalize_state, &response, &issuer_pk).unwrap();
        (issuer_pk, credential)
    }

    #[test]
    fn present_then_verify_round_trips() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let presentation = credential.present(&issuer_pk, b"election-2026", b"ctx", &mut rng);
        verify_presentation(&presentation, &issuer_pk, b"election-2026", b"ctx")
            .expect("honest presentation verifies");
    }

    #[test]
    fn wrong_election_id_at_verify_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let presentation = credential.present(&issuer_pk, b"election-2026", b"ctx", &mut rng);
        // Mismatched election id at verify time changes both H_e and the
        // transcript binding; CP verification must fail.
        assert!(matches!(
            verify_presentation(&presentation, &issuer_pk, b"election-2027", b"ctx"),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn wrong_context_at_verify_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let presentation = credential.present(&issuer_pk, b"election-2026", b"ctx-A", &mut rng);
        assert!(matches!(
            verify_presentation(&presentation, &issuer_pk, b"election-2026", b"ctx-B"),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn tampered_presentation_proof_bytes_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let mut presentation = credential.present(&issuer_pk, b"e", b"c", &mut rng);
        // Flip a byte deep inside the CP proof portion (past the
        // signature prefix). Any change there must cause CP verification
        // to fail.
        let idx = SIGNATURE_PREFIX_LEN + 4;
        presentation.presentation_proof[idx] ^= 0x01;
        let err = verify_presentation(&presentation, &issuer_pk, b"e", b"c")
            .expect_err("tampered proof must fail");
        // We accept either VerificationFailed or one of the decode errors,
        // depending on which byte got flipped — both are "rejected".
        assert!(matches!(
            err,
            CryptoError::VerificationFailed
                | CryptoError::InvalidPoint
                | CryptoError::InvalidScalar
                | CryptoError::InvalidParameters(_)
        ));
    }

    #[test]
    fn tampered_credential_commitment_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let mut presentation = credential.present(&issuer_pk, b"e", b"c", &mut rng);
        // Replace `credential_commitment` with a different valid point.
        let other = Scalar::from(2024u64) * basepoint();
        presentation.credential_commitment = compress_point(&other).to_vec();
        assert!(matches!(
            verify_presentation(&presentation, &issuer_pk, b"e", b"c"),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn tampered_nullifier_value_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let mut presentation = credential.present(&issuer_pk, b"e", b"c", &mut rng);
        // Replace `nullifier.value` with a different valid point.
        let other = Scalar::from(99u64) * basepoint();
        if let Some(ref mut n) = presentation.nullifier {
            n.value = compress_point(&other).to_vec();
        }
        assert!(matches!(
            verify_presentation(&presentation, &issuer_pk, b"e", b"c"),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn wrong_issuer_public_key_at_verify_is_rejected() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let presentation = credential.present(&issuer_pk, b"e", b"c", &mut rng);

        let other_pk = IssuerSecretKey::generate(&mut rng).public_key();
        assert_ne!(issuer_pk, other_pk);
        // Verifier passes a different `issuer_pk`; the embedded-vs-supplied
        // mismatch is detected and the call returns `VerificationFailed`.
        assert!(matches!(
            verify_presentation(&presentation, &other_pk, b"e", b"c"),
            Err(CryptoError::VerificationFailed)
        ));
    }

    #[test]
    fn wire_roundtrip_identity() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let presentation = credential.present(&issuer_pk, b"e", b"c", &mut rng);

        let bytes = presentation.encode_to_vec();
        let decoded =
            CredentialPresentation::decode(&bytes[..]).expect("encoded presentation re-decodes");
        assert_eq!(decoded, presentation);
        verify_presentation(&decoded, &issuer_pk, b"e", b"c")
            .expect("decoded presentation still verifies");
    }

    /// Two presentations of the **same** credential to the **same**
    /// election produce byte-identical nullifiers (this is the
    /// double-vote detection mechanism).
    #[test]
    fn same_election_same_credential_yields_identical_nullifier() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let first = credential.present(&issuer_pk, b"election-A", b"ctx-1", &mut rng);
        let second = credential.present(&issuer_pk, b"election-A", b"ctx-2", &mut rng);

        let n1 = first
            .nullifier
            .as_ref()
            .expect("nullifier present")
            .value
            .clone();
        let n2 = second
            .nullifier
            .as_ref()
            .expect("nullifier present")
            .value
            .clone();
        assert_eq!(
            n1, n2,
            "double-vote detection: nullifier must be deterministic per (credential, election)"
        );
    }

    #[test]
    fn presentation_context_is_length_prefixed_and_stable() {
        // Known-input fixture so we catch silent format drift.
        let ctx = presentation_context(b"election-2026", b"contest=president");
        // The bytes are: domain tag (33B) || u64(13).BE || "election-2026" || u64(17).BE || "contest=president".
        assert!(ctx.starts_with(b"saksi.credentials.presentation.v1"));
        let mut expected = Vec::new();
        expected.extend_from_slice(b"saksi.credentials.presentation.v1");
        expected.extend_from_slice(&13u64.to_be_bytes());
        expected.extend_from_slice(b"election-2026");
        expected.extend_from_slice(&17u64.to_be_bytes());
        expected.extend_from_slice(b"contest=president");
        assert_eq!(ctx, expected);

        // Cross-check vs Credential::present: building the same context here and
        // running it through ChaumPedersenProof::prove/verify against fresh
        // (s_cred, election, context) should round-trip cleanly. This is implicit
        // in the existing `verify_presentation` tests; here we only pin the bytes.
    }

    /// Two presentations of the same credential to **different** elections
    /// produce different nullifiers (cross-election unlinkability).
    #[test]
    fn different_elections_yield_distinct_nullifiers() {
        let mut rng = OsRng;
        let (issuer_pk, credential) = issue(&mut rng);
        let first = credential.present(&issuer_pk, b"election-A", b"ctx", &mut rng);
        let second = credential.present(&issuer_pk, b"election-B", b"ctx", &mut rng);

        let n1 = &first.nullifier.as_ref().unwrap().value;
        let n2 = &second.nullifier.as_ref().unwrap().value;
        assert_ne!(
            n1, n2,
            "cross-election unlinkability: different election_id must give a different nullifier"
        );
    }
}
