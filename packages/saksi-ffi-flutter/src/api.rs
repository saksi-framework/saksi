use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use saksi_credentials::{
    derive_nullifier as credentials_derive_nullifier,
    issuance::{Credential, IssuerPublicKey},
    nullifier::compress_nullifier,
};
use saksi_crypto::{
    benaloh::BenalohCommitment,
    elgamal::{encrypt, Ciphertext, Plaintext, PublicKey, SecretKey},
    group::{compress_point, point_from_compressed, scalar_from_canonical_bytes},
    nizk::cds::CDSProof,
};
use saksi_protocol::encode as encode_protocol_message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct KeypairDto {
    pub secret_scalar: u64,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CiphertextDto {
    pub pad: String,
    pub data: String,
}

/// Legacy v1 proof handle. **Deprecated:** returns a SHA-256 placeholder, not a
/// real proof. New callers should use the `*_v2` entry points which emit real
/// Saksi cryptographic artifacts.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofHandleDto {
    pub label: String,
    pub digest: String,
}

/// Wire-encoded cryptographic proof returned by the v2 FFI entry points. The
/// caller treats `proof_bytes` as opaque — verification is performed by the
/// auditor against the corresponding wire schema.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofBytesDto {
    /// Stable label identifying the proof family and version
    /// (e.g. `saksi.ffi.flutter.cds-proof.v2`).
    pub label: String,
    /// Hex-encoded canonical wire bytes for the proof.
    pub proof_bytes: String,
}

/// Reveal half of a real Benaloh cast-or-challenge ceremony: the cleartext
/// inputs plus the Merlin transcript digest that the device committed to at
/// commit time.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BenalohChallengeRevealDto {
    /// Stable label (`saksi.ffi.flutter.benaloh-challenge.v2`).
    pub label: String,
    /// The ciphertext the device produced. Hex-encoded `(pad, data)`.
    pub ciphertext: CiphertextDto,
    /// Hex-encoded compressed encoding of the plaintext point.
    pub plaintext_point_hex: String,
    /// Hex-encoded canonical encoding of the ElGamal randomness scalar.
    pub randomness_hex: String,
    /// Hex-encoded 32-byte transcript digest bound to
    /// `(public_key, plaintext_label, context, ciphertext)`.
    pub transcript_digest_hex: String,
}

/// Wire-encoded `CredentialPresentation` plus its derived nullifier, returned
/// by [`present_credential_v2`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CredentialPresentationDto {
    /// Stable label (`saksi.ffi.flutter.credential-presentation.v2`).
    pub label: String,
    /// Hex-encoded canonical bytes of the `saksi.protocol.v1.CredentialPresentation`
    /// protobuf message.
    pub wire_bytes_hex: String,
    /// Hex-encoded 32-byte compressed nullifier point
    /// (`s_cred · H_e` where `H_e = nullifier_h(election_id)`).
    pub nullifier_hex: String,
}

// ---------------------------------------------------------------------------
// Real (already-correct) entry points
// ---------------------------------------------------------------------------

pub fn keygen_from_scalar(secret_scalar: u64) -> KeypairDto {
    let secret_key = SecretKey::from_scalar(Scalar::from(secret_scalar));
    KeypairDto {
        secret_scalar,
        public_key: hex_lower(&secret_key.public_key().to_compressed_bytes()),
    }
}

pub fn encrypt_ballot(
    public_key: String,
    choice: u64,
    randomness: u64,
) -> Result<CiphertextDto, String> {
    let (ciphertext, _r, _pk) = encrypt_ballot_internal(&public_key, choice, randomness)?;
    Ok(ciphertext_to_dto(&ciphertext))
}

pub fn verify_tracking_code_receipt(
    expected_tracking_code: String,
    received_tracking_code: String,
) -> bool {
    expected_tracking_code == received_tracking_code
}

// ---------------------------------------------------------------------------
// v1 placeholders (deprecated — kept for soft migration on the BalotaChain side)
// ---------------------------------------------------------------------------

#[deprecated(note = "replaced by generate_cds_proof_v2 in Phase F; SHA-256 placeholder")]
pub fn generate_cds_proof(ciphertext: CiphertextDto, contest_id: String) -> ProofHandleDto {
    digest_handle(
        "saksi.ffi.flutter.cds-proof.v1",
        &[ciphertext.pad, ciphertext.data, contest_id],
    )
}

#[deprecated(note = "replaced by perform_benaloh_challenge_v2 in Phase F; SHA-256 placeholder")]
pub fn perform_benaloh_challenge(
    ciphertext: CiphertextDto,
    challenge_nonce: String,
) -> ProofHandleDto {
    digest_handle(
        "saksi.ffi.flutter.benaloh-challenge.v1",
        &[ciphertext.pad, ciphertext.data, challenge_nonce],
    )
}

#[deprecated(note = "replaced by derive_nullifier_v2 in Phase F; SHA-256 placeholder")]
pub fn derive_nullifier(credential_commitment: String, election_id: String) -> String {
    digest_handle(
        "saksi.ffi.flutter.nullifier.v1",
        &[credential_commitment, election_id],
    )
    .digest
}

#[deprecated(note = "replaced by present_credential_v2 in Phase F; SHA-256 placeholder")]
pub fn present_credential(credential_commitment: String, election_id: String) -> ProofHandleDto {
    digest_handle(
        "saksi.ffi.flutter.credential-presentation.v1",
        &[credential_commitment, election_id],
    )
}

// ---------------------------------------------------------------------------
// v2 entry points (real Saksi crypto)
// ---------------------------------------------------------------------------

/// Real Cramer-Damgård-Schoenmakers OR-proof that a binary contest ciphertext
/// encrypts a value in `{0, 1}` under `public_key_hex`. The caller must pass
/// the same `(choice, randomness)` that produced the ciphertext.
///
/// `contest_id` is bound into the prover's Fiat-Shamir transcript via its
/// UTF-8 bytes, so any later mismatch by the auditor causes verification to
/// fail.
///
/// Returns the canonical wire-encoded [`saksi_protocol::CDSProof`] bytes as
/// hex inside a [`ProofBytesDto`].
pub fn generate_cds_proof_v2(
    public_key_hex: String,
    choice: u64,
    randomness: u64,
    contest_id: String,
) -> Result<ProofBytesDto, String> {
    if choice > 1 {
        return Err("CDS v2 only supports binary contests (choice ∈ {0, 1})".to_owned());
    }
    let (ciphertext, r_scalar, public_key) =
        encrypt_ballot_internal(&public_key_hex, choice, randomness)?;
    let choice_set = vec![Scalar::ZERO, Scalar::ONE];
    let true_index = choice as usize;
    let proof = CDSProof::prove(
        &public_key,
        &ciphertext,
        &choice_set,
        true_index,
        &r_scalar,
        contest_id.as_bytes(),
        &mut OsRng,
    )
    .map_err(|err| err.to_string())?;
    let wire = proof.to_wire();
    let proof_bytes = encode_protocol_message(&wire);
    Ok(ProofBytesDto {
        label: "saksi.ffi.flutter.cds-proof.v2".to_owned(),
        proof_bytes: hex_lower(&proof_bytes),
    })
}

/// Runs the real Benaloh cast-or-challenge commitment + challenge flow:
/// commits to `(public_key, plaintext_label, context, ciphertext)` via Merlin,
/// then reveals the underlying randomness so an external verifier can
/// re-encrypt and check.
///
/// `plaintext_label` and `context` are passed into the transcript as UTF-8
/// bytes.
pub fn perform_benaloh_challenge_v2(
    public_key_hex: String,
    choice: u64,
    randomness: u64,
    plaintext_label: String,
    context: String,
) -> Result<BenalohChallengeRevealDto, String> {
    let public_key_point = decode_point(&public_key_hex)?;
    let public_key = PublicKey::from_point(public_key_point);
    let plaintext = Plaintext::from_small_integer(choice);
    let r_scalar = Scalar::from(randomness);

    let commitment = BenalohCommitment::commit(
        &public_key,
        plaintext,
        plaintext_label.as_bytes(),
        context.as_bytes(),
        r_scalar,
    );
    let reveal = commitment.challenge();
    let ciphertext_dto = ciphertext_to_dto(&reveal.ciphertext);
    let plaintext_point_hex = hex_lower(&compress_point(reveal.plaintext.as_point()));
    let randomness_hex = hex_lower(&reveal.randomness.to_bytes());
    let transcript_digest_hex = hex_lower(&reveal.transcript_digest);

    Ok(BenalohChallengeRevealDto {
        label: "saksi.ffi.flutter.benaloh-challenge.v2".to_owned(),
        ciphertext: ciphertext_dto,
        plaintext_point_hex,
        randomness_hex,
        transcript_digest_hex,
    })
}

/// Derives the per-election nullifier `n = s_cred · H_e` where
/// `H_e = nullifier_h(election_id)`. Returns the 32-byte compressed
/// ristretto encoding as hex.
///
/// `election_id` is mixed into the hash-to-point via its UTF-8 bytes; the
/// caller is responsible for using a canonical election identifier.
pub fn derive_nullifier_v2(
    credential_secret_scalar_hex: String,
    election_id: String,
) -> Result<String, String> {
    let s_cred = decode_scalar(&credential_secret_scalar_hex)?;
    let nullifier = credentials_derive_nullifier(&s_cred, election_id.as_bytes());
    Ok(hex_lower(&compress_nullifier(&nullifier)))
}

/// Builds a real [`saksi_protocol::CredentialPresentation`] from the holder
/// secret credential `s_cred` and the issuer Schnorr signature `(R', s_sig)`.
///
/// `context` is bound into the presentation transcript as UTF-8 bytes (the
/// same framing the auditor and bulletin board use).
///
/// Returns the canonical wire bytes plus the derived nullifier (so the caller
/// can submit both atomically).
///
/// # Errors
/// - `Err("...")` if any hex input is malformed.
/// - `Err("...")` if the supplied signature does not verify against
///   `issuer_public_key_hex` on the commitment `s_cred · G`. This guards
///   against the FFI emitting a presentation that will be rejected on-chain.
pub fn present_credential_v2(
    credential_secret_scalar_hex: String,
    credential_signature_hex: String,
    issuer_public_key_hex: String,
    election_id: String,
    context: String,
) -> Result<CredentialPresentationDto, String> {
    let s_cred = decode_scalar(&credential_secret_scalar_hex)?;
    let sig_bytes = parse_hex(&credential_signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err("credential signature must be exactly 64 bytes (R' || s_sig)".to_owned());
    }
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    let signature_r = point_from_compressed(r_bytes).map_err(|err| err.to_string())?;
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig_bytes[32..]);
    let signature_s = scalar_from_canonical_bytes(s_bytes).map_err(|err| err.to_string())?;

    let issuer_pk_point = decode_point(&issuer_public_key_hex)?;
    let issuer_pk = IssuerPublicKey(issuer_pk_point);

    // Rebuild the canonical Credential from the supplied parts and verify the
    // issuer signature *before* producing the presentation. This is the FFI's
    // guarantee that we never emit a presentation the bulletin board would
    // reject on submit, and it surfaces a tampered signature as
    // `VerificationFailed` at the boundary (matching the v1 test expectation).
    let credential = Credential::from_parts(s_cred, signature_r, signature_s);
    credential
        .verify_against_issuer(&issuer_pk)
        .map_err(|err| err.to_string())?;

    // Run the real present(). This emits the canonical wire bytes and the same
    // nullifier `derive_nullifier_v2` would produce — by construction.
    let presentation = credential.present(
        &issuer_pk,
        election_id.as_bytes(),
        context.as_bytes(),
        &mut OsRng,
    );

    let nullifier_hex = presentation
        .nullifier
        .as_ref()
        .map(|n| hex_lower(&n.value))
        .unwrap_or_default();
    let wire_bytes = encode_protocol_message(&presentation);

    Ok(CredentialPresentationDto {
        label: "saksi.ffi.flutter.credential-presentation.v2".to_owned(),
        wire_bytes_hex: hex_lower(&wire_bytes),
        nullifier_hex,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Shared ElGamal-encryption helper: parses the hex public key, encrypts the
/// `choice` under randomness `r`, and returns the raw `(Ciphertext, r,
/// PublicKey)` triple so v2 provers can reuse them without re-parsing hex.
fn encrypt_ballot_internal(
    public_key_hex: &str,
    choice: u64,
    randomness: u64,
) -> Result<(Ciphertext, Scalar, PublicKey), String> {
    let point = decode_point(public_key_hex)?;
    let public_key = PublicKey::from_point(point);
    let r_scalar = Scalar::from(randomness);
    let ciphertext = encrypt(&public_key, Plaintext::from_small_integer(choice), r_scalar);
    Ok((ciphertext, r_scalar, public_key))
}

fn ciphertext_to_dto(ciphertext: &Ciphertext) -> CiphertextDto {
    let (pad, data) = ciphertext.to_compressed_bytes();
    CiphertextDto {
        pad: hex_lower(&pad),
        data: hex_lower(&data),
    }
}

fn digest_handle(label: &'static str, parts: &[String]) -> ProofHandleDto {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    ProofHandleDto {
        label: label.to_owned(),
        digest: hex_lower(&hasher.finalize()),
    }
}

fn decode_point(input: &str) -> Result<curve25519_dalek::ristretto::RistrettoPoint, String> {
    point_from_compressed(parse_32_byte_hex(input)?).map_err(|err| err.to_string())
}

fn decode_scalar(input: &str) -> Result<Scalar, String> {
    scalar_from_canonical_bytes(parse_32_byte_hex(input)?).map_err(|err| err.to_string())
}

fn parse_32_byte_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex(input)?;
    bytes
        .try_into()
        .map_err(|_| "expected 32-byte hex string".to_owned())
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex input must have even length".to_owned());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_owned()),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::{encrypt_ballot, keygen_from_scalar, perform_benaloh_challenge, CiphertextDto};

    #[test]
    fn flutter_encrypt_ballot_round_trips_to_ciphertext_dto() {
        let keypair = keygen_from_scalar(42);
        let ciphertext = encrypt_ballot(keypair.public_key, 1, 99).expect("encrypts");

        assert_eq!(
            ciphertext.pad,
            "0e1d5b2771666dd340a8285c3d315e94f21c3b48be9c5d65352eb952541db019"
        );
        assert_eq!(
            ciphertext.data,
            "8af8a8933f35789af543aa4aeace1b033a03e87bb603bc77f8bb85e2b2bff92a"
        );
    }

    #[test]
    fn flutter_benaloh_challenge_returns_stable_handle() {
        let handle = perform_benaloh_challenge(
            CiphertextDto {
                pad: "pad".to_owned(),
                data: "data".to_owned(),
            },
            "nonce".to_owned(),
        );

        assert_eq!(handle.label, "saksi.ffi.flutter.benaloh-challenge.v1");
        assert_eq!(handle.digest.len(), 64);
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use merlin::Transcript;
    use prost::Message;
    use saksi_credentials::issuance::IssuerSecretKey;
    use saksi_credentials::verify_presentation;
    use saksi_crypto::benaloh::BenalohCommitment;
    use saksi_crypto::elgamal::{self, encrypt, Plaintext, SecretKey};
    use saksi_crypto::group::basepoint;
    use saksi_protocol::{CDSProof as ProtoCDSProof, CredentialPresentation};

    fn keypair_hex(scalar: u64) -> (String, SecretKey) {
        let sk = SecretKey::from_scalar(Scalar::from(scalar));
        let pk_hex = hex_lower(&sk.public_key().to_compressed_bytes());
        (pk_hex, sk)
    }

    // -- 1: CDS v2 happy ----------------------------------------------------

    #[test]
    fn cds_proof_v2_happy_choice_one_verifies() {
        let (pk_hex, sk) = keypair_hex(11);
        let randomness: u64 = 7777;
        let dto = generate_cds_proof_v2(pk_hex.clone(), 1, randomness, "contest-A".to_owned())
            .expect("CDS v2 prove ok");
        assert_eq!(dto.label, "saksi.ffi.flutter.cds-proof.v2");

        // Re-derive the ciphertext that the FFI would have produced and verify
        // the proof against it.
        let ct = encrypt(
            &sk.public_key(),
            Plaintext::from_small_integer(1),
            Scalar::from(randomness),
        );
        let proof_bytes = parse_hex(&dto.proof_bytes).expect("hex");
        let wire = ProtoCDSProof::decode(&proof_bytes[..]).expect("decode CDS proof");
        let proof = CDSProof::from_wire(&wire).expect("from_wire");

        let choice_set = vec![Scalar::ZERO, Scalar::ONE];
        proof
            .verify(&sk.public_key(), &ct, &choice_set, b"contest-A")
            .expect("CDS v2 verifies independently");
    }

    #[test]
    fn cds_proof_v2_happy_choice_zero_verifies() {
        let (pk_hex, sk) = keypair_hex(23);
        let randomness: u64 = 4242;
        let dto =
            generate_cds_proof_v2(pk_hex, 0, randomness, "c0".to_owned()).expect("CDS v2 prove ok");
        let ct = encrypt(
            &sk.public_key(),
            Plaintext::from_small_integer(0),
            Scalar::from(randomness),
        );
        let proof_bytes = parse_hex(&dto.proof_bytes).expect("hex");
        let wire = ProtoCDSProof::decode(&proof_bytes[..]).expect("decode");
        let proof = CDSProof::from_wire(&wire).expect("from_wire");
        let choice_set = vec![Scalar::ZERO, Scalar::ONE];
        proof
            .verify(&sk.public_key(), &ct, &choice_set, b"c0")
            .expect("verifies");
    }

    // -- 2: CDS v2 invalid input -------------------------------------------

    #[test]
    fn cds_proof_v2_rejects_non_binary_choice() {
        let (pk_hex, _) = keypair_hex(11);
        let err = generate_cds_proof_v2(pk_hex, 2, 1, "x".to_owned())
            .expect_err("non-binary choice must be rejected");
        assert!(err.contains("binary"));
    }

    // -- 3: Benaloh v2 happy ------------------------------------------------

    #[test]
    fn benaloh_v2_happy_digest_matches_and_reencryption_matches() {
        let (pk_hex, sk) = keypair_hex(31);
        let pk = sk.public_key();
        let randomness: u64 = 999;
        let dto = perform_benaloh_challenge_v2(
            pk_hex,
            1,
            randomness,
            "contest=president,choice=alice".to_owned(),
            "election=demo,device=k01,ballot=1".to_owned(),
        )
        .expect("benaloh v2 ok");
        assert_eq!(dto.label, "saksi.ffi.flutter.benaloh-challenge.v2");

        // 1. Digest matches the commitment's digest for the same inputs.
        let commitment = BenalohCommitment::commit(
            &pk,
            Plaintext::from_small_integer(1),
            b"contest=president,choice=alice",
            b"election=demo,device=k01,ballot=1",
            Scalar::from(randomness),
        );
        let expected_digest_hex = hex_lower(&commitment.transcript_digest());
        assert_eq!(dto.transcript_digest_hex, expected_digest_hex);

        // 2. Re-encrypt with the revealed randomness and verify the ciphertext
        //    matches what the device emitted.
        let revealed_r = decode_scalar(&dto.randomness_hex).expect("scalar");
        let re_ct = encrypt(&pk, Plaintext::from_small_integer(1), revealed_r);
        let (pad, data) = re_ct.to_compressed_bytes();
        assert_eq!(dto.ciphertext.pad, hex_lower(&pad));
        assert_eq!(dto.ciphertext.data, hex_lower(&data));

        // Sanity: revealed scalar equals the original randomness scalar.
        assert_eq!(revealed_r, Scalar::from(randomness));

        // Sanity: digest is non-empty and the ciphertext is well-formed.
        assert!(elgamal::ciphertexts_equal(&re_ct, commitment.ciphertext()));
    }

    // -- 4, 5: nullifier v2 determinism + cross-election separation --------

    #[test]
    fn nullifier_v2_is_deterministic() {
        let s_hex = hex_lower(&Scalar::from(987u64).to_bytes());
        let a = derive_nullifier_v2(s_hex.clone(), "election-2026".to_owned()).unwrap();
        let b = derive_nullifier_v2(s_hex, "election-2026".to_owned()).unwrap();
        assert_eq!(a, b);
        // Sanity: 32-byte point hex.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn nullifier_v2_separates_elections() {
        let s_hex = hex_lower(&Scalar::from(987u64).to_bytes());
        let a = derive_nullifier_v2(s_hex.clone(), "election-2026-A".to_owned()).unwrap();
        let b = derive_nullifier_v2(s_hex, "election-2026-B".to_owned()).unwrap();
        assert_ne!(a, b);
    }

    // -- 6: present_credential_v2 happy ------------------------------------

    /// Replays the `compute_issuance_challenge` transcript binding from
    /// `saksi-credentials::issuance`, so the test can directly forge a valid
    /// Schnorr signature on `C = s_cred · G` under a known issuer secret
    /// scalar — bypassing the full blind-issuance dance for test setup
    /// only. (`Credential` has no public constructor and `s_cred` is
    /// `pub(crate)`, so we cannot run the real issuance flow and then read
    /// back the secret scalar.)
    fn compute_issuance_challenge(
        issuer_pk_point: &RistrettoPoint,
        commitment: &RistrettoPoint,
        r_prime: &RistrettoPoint,
    ) -> Scalar {
        let mut transcript = Transcript::new(b"saksi.credentials.issuance.v1");
        transcript.append_message(b"issuer-pk", &compress_point(issuer_pk_point));
        transcript.append_message(b"commitment", &compress_point(commitment));
        transcript.append_message(b"r-prime", &compress_point(r_prime));
        let mut buf = [0u8; 64];
        transcript.challenge_bytes(b"challenge", &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn issue_real_credential() -> (IssuerPublicKey, Scalar, [u8; 64]) {
        // Known issuer secret scalar (test-only — never do this in production).
        let issuer_secret = Scalar::from(0xC0_FFEE_u64);
        let issuer_sk = IssuerSecretKey::from_scalar(issuer_secret);
        let issuer_pk = issuer_sk.public_key();
        let issuer_pk_point = *issuer_pk.as_point();

        // Voter's credential.
        let s_cred = Scalar::from(0xBA_BE_u64);
        let g = basepoint();
        let commitment = s_cred * g;

        // Plain (non-blind) Schnorr signature on `commitment` under
        // `issuer_secret`, using the exact same transcript binding the
        // credentials crate uses for the unblinded signature:
        //
        //   k <- random
        //   R' = k · G
        //   e  = H(transcript, Pk_i, C, R')
        //   s_sig = k + e · x_i
        //
        // Verification (`s_sig · G == R' + e · Pk_i`) succeeds by
        // construction.
        let k = Scalar::from(0xDEAD_BEEF_u64);
        let r_prime = k * g;
        let e = compute_issuance_challenge(&issuer_pk_point, &commitment, &r_prime);
        let s_sig = k + e * issuer_secret;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&compress_point(&r_prime));
        sig_bytes[32..].copy_from_slice(&s_sig.to_bytes());
        (issuer_pk, s_cred, sig_bytes)
    }

    #[test]
    fn present_credential_v2_happy_verifies_via_credentials_verifier() {
        let (issuer_pk, s_cred, sig_bytes) = issue_real_credential();
        let issuer_pk_hex = hex_lower(&compress_point(issuer_pk.as_point()));
        let s_hex = hex_lower(&s_cred.to_bytes());
        let sig_hex = hex_lower(&sig_bytes);

        let dto = present_credential_v2(
            s_hex,
            sig_hex,
            issuer_pk_hex,
            "election-2026".to_owned(),
            "ctx".to_owned(),
        )
        .expect("present_credential_v2 ok");
        assert_eq!(dto.label, "saksi.ffi.flutter.credential-presentation.v2");

        // Decode the wire bytes back into a CredentialPresentation and verify.
        let wire_bytes = parse_hex(&dto.wire_bytes_hex).expect("hex");
        let presentation =
            CredentialPresentation::decode(&wire_bytes[..]).expect("decode presentation");
        verify_presentation(&presentation, &issuer_pk, b"election-2026", b"ctx")
            .expect("presentation verifies under credentials verifier");

        // Sanity: returned nullifier matches the presentation's nullifier.
        let null_in_wire = hex_lower(&presentation.nullifier.unwrap().value);
        assert_eq!(dto.nullifier_hex, null_in_wire);
    }

    // -- 7: present_credential_v2 rejects tampered signature ---------------

    #[test]
    fn present_credential_v2_rejects_tampered_signature() {
        let (issuer_pk, s_cred, mut sig_bytes) = issue_real_credential();
        // Flip a byte in the s_sig half (avoid the R' point so we don't trip
        // the "InvalidPoint" decode error first; we want VerificationFailed).
        sig_bytes[40] ^= 0x01;

        let issuer_pk_hex = hex_lower(&compress_point(issuer_pk.as_point()));
        let s_hex = hex_lower(&s_cred.to_bytes());
        let sig_hex = hex_lower(&sig_bytes);

        let err = present_credential_v2(
            s_hex,
            sig_hex,
            issuer_pk_hex,
            "e".to_owned(),
            "c".to_owned(),
        )
        .expect_err("tampered signature must be rejected");
        // CryptoError::VerificationFailed::to_string() begins with "verification".
        assert!(
            err.to_lowercase().contains("verification"),
            "unexpected error: {err}"
        );
    }

    // Sanity that the tampered Compressed point decodes (CompressedRistretto
    // happily decodes any 32 bytes that lie on the curve; this is here so the
    // tampered-signature test doesn't accidentally hit the InvalidPoint path
    // and silently pass for the wrong reason).
    #[test]
    fn sanity_zero_point_decodes() {
        let zero: [u8; 32] = CompressedRistretto::default().to_bytes();
        assert!(point_from_compressed(zero).is_ok());
    }
}
