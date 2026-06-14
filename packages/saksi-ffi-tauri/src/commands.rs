use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;
use saksi_crypto::{
    group::{basepoint, compress_point, point_from_compressed, scalar_from_canonical_bytes},
    nizk::chaum_pedersen::ChaumPedersenProof,
    transcript::{TRANSCRIPT_LABEL_CHAUM_PEDERSEN, TRANSCRIPT_LABEL_DKG},
};
use saksi_protocol::{
    decode as decode_protocol_message, encode as encode_protocol_message,
    ChaumPedersenProof as ProtoChaumPedersenProof, DKGTranscript, PartialDecryption, WIRE_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CiphertextDto {
    pub pad: String,
    pub data: String,
}

/// Legacy v1 partial-decryption DTO. **Deprecated** — emits the share but
/// **no Chaum-Pedersen proof of correctness**. New callers should use
/// [`PartialDecryptionV2Dto`] via [`partial_decrypt_v2`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialDecryptionDto {
    pub trustee_id: String,
    pub share: String,
}

/// v2 partial-decryption DTO: trustee identity, the share point in
/// compressed form, and the canonical wire bytes of a
/// [`saksi_protocol::ChaumPedersenProof`] that ties the share to the
/// trustee's published public share `pub_i = s_i · G`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialDecryptionV2Dto {
    pub trustee_id: String,
    /// Identifier of the contest whose aggregate ciphertext this share decrypts.
    pub contest_id: String,
    /// Hex-encoded 32-byte compressed ristretto encoding of the share point
    /// `D_i = s_i · R` where `R` is the ciphertext pad.
    pub share_hex: String,
    /// Hex-encoded canonical bytes of the wire
    /// `saksi.protocol.v1.ChaumPedersenProof` over `(G, R, pub_i, D_i)`.
    pub proof_bytes_hex: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct TranscriptPublicationDto {
    pub label: String,
    pub digest: String,
}

// ---------------------------------------------------------------------------
// v1 placeholders (deprecated — kept for soft migration on the BalotaChain side)
// ---------------------------------------------------------------------------

#[deprecated(note = "replaced by partial_decrypt_v2 in Phase F; no proof attached")]
pub fn partial_decrypt(
    trustee_id: String,
    secret_share: u64,
    ciphertext: CiphertextDto,
) -> Result<PartialDecryptionDto, String> {
    let pad = point_from_compressed(parse_32_byte_hex(&ciphertext.pad)?)
        .map_err(|err| err.to_string())?;
    let share = Scalar::from(secret_share) * pad;
    Ok(PartialDecryptionDto {
        trustee_id,
        share: hex_lower(&share.compress().to_bytes()),
    })
}

#[deprecated(note = "replaced by publish_dkg_transcript_v2 in Phase F; SHA-256 placeholder")]
pub fn publish_dkg_transcript(
    trustee_id: String,
    transcript_bytes: String,
) -> TranscriptPublicationDto {
    digest_handle(
        "saksi.ffi.tauri.dkg-transcript.v1",
        &[trustee_id, transcript_bytes],
    )
}

#[deprecated(note = "replaced by publish_partial_decryption_v2 in Phase F; SHA-256 placeholder")]
pub fn publish_partial_decryption(partial: PartialDecryptionDto) -> TranscriptPublicationDto {
    digest_handle(
        "saksi.ffi.tauri.partial-decryption.v1",
        &[partial.trustee_id, partial.share],
    )
}

// ---------------------------------------------------------------------------
// v2 entry points (real Saksi crypto)
// ---------------------------------------------------------------------------

/// Computes the partial decryption share `D_i = s_i · R` (where `R` is the
/// ciphertext pad) **and** a Chaum-Pedersen NIZK over `(G, R, pub_i, D_i)`
/// proving that the same `s_i` underlies the trustee's published public
/// share `pub_i = s_i · G`.
///
/// `context` is fed into the prover's transcript as UTF-8 bytes (the
/// trustee should bind, e.g., the election id and share index).
///
/// # Errors
/// - `Err("...")` on malformed hex inputs.
/// - `Err("...")` if `trustee_share_public_key_hex` does NOT match
///   `secret_share · G`. This guards against producing a proof the auditor
///   would reject.
pub fn partial_decrypt_v2(
    trustee_id: String,
    contest_id: String,
    secret_share_hex: String,
    trustee_share_public_key_hex: String,
    ciphertext: CiphertextDto,
    context: String,
) -> Result<PartialDecryptionV2Dto, String> {
    let secret_share = decode_scalar(&secret_share_hex)?;
    let pub_share = decode_point(&trustee_share_public_key_hex)?;
    let pad = decode_point(&ciphertext.pad)?;

    // Sanity check: pub_share must equal secret_share · G.
    let expected_pub = secret_share * basepoint();
    if expected_pub != pub_share {
        return Err(
            "trustee_share_public_key does not match secret_share * G; refusing to emit a proof that won't verify"
                .to_owned(),
        );
    }

    // D_i = s_i · R.
    let share_point = secret_share * pad;

    // Chaum-Pedersen proof: A = s_i · G = pub_i, B = s_i · R = share_point.
    let g = basepoint();
    let proof = ChaumPedersenProof::prove(
        &g,
        &pad,
        &pub_share,
        &share_point,
        &secret_share,
        context.as_bytes(),
        &mut OsRng,
    );
    let proof_bytes = encode_protocol_message(&proof.to_wire());

    Ok(PartialDecryptionV2Dto {
        trustee_id,
        contest_id,
        share_hex: hex_lower(&compress_point(&share_point)),
        proof_bytes_hex: hex_lower(&proof_bytes),
    })
}

/// Validates `transcript_wire_bytes_hex` as a canonical
/// [`saksi_protocol::DKGTranscript`] message, re-serializes it (so the
/// caller can rely on canonical bytes), and emits a Merlin-bound digest
/// under [`TRANSCRIPT_LABEL_DKG`] (`saksi.dkg.pedersen.v1`).
///
/// `trustee_id` is mixed into the digest binding so two trustees publishing
/// the same transcript shape will not produce the same digest.
///
/// # Errors
/// - `Err("...")` if the hex does not decode, the protobuf does not parse,
///   or the embedded `version` differs from [`WIRE_VERSION`].
pub fn publish_dkg_transcript_v2(
    trustee_id: String,
    transcript_wire_bytes_hex: String,
) -> Result<TranscriptPublicationDto, String> {
    let wire_bytes = parse_hex(&transcript_wire_bytes_hex)?;
    let parsed: DKGTranscript =
        decode_protocol_message(&wire_bytes).map_err(|err| err.to_string())?;
    if parsed.version != WIRE_VERSION {
        return Err(format!(
            "unsupported DKGTranscript wire version: expected {WIRE_VERSION}, got {}",
            parsed.version
        ));
    }
    let canonical = encode_protocol_message(&parsed);

    let mut transcript = Transcript::new(TRANSCRIPT_LABEL_DKG);
    transcript.append_message(b"trustee_id", trustee_id.as_bytes());
    transcript.append_message(b"dkg_transcript", &canonical);
    let mut digest = [0u8; 32];
    transcript.challenge_bytes(b"publication_digest", &mut digest);

    Ok(TranscriptPublicationDto {
        label: "saksi.ffi.tauri.dkg-transcript.v2".to_owned(),
        digest: hex_lower(&digest),
    })
}

/// Serializes a v2 [`PartialDecryptionV2Dto`] as a canonical
/// [`saksi_protocol::PartialDecryption`] and emits a Merlin-bound digest
/// under [`TRANSCRIPT_LABEL_CHAUM_PEDERSEN`] (`saksi.nizk.chaum-pedersen.v1`).
///
/// # Errors
/// - `Err("...")` on malformed hex inputs or a wire-version mismatch in the
///   embedded proof bytes.
pub fn publish_partial_decryption_v2(
    partial: PartialDecryptionV2Dto,
) -> Result<TranscriptPublicationDto, String> {
    let share_bytes = parse_32_byte_hex(&partial.share_hex)?;
    // Validate share is a canonical ristretto point.
    point_from_compressed(share_bytes).map_err(|err| err.to_string())?;

    let proof_bytes = parse_hex(&partial.proof_bytes_hex)?;
    let proof_wire: ProtoChaumPedersenProof =
        decode_protocol_message(&proof_bytes).map_err(|err| err.to_string())?;
    if proof_wire.version != WIRE_VERSION {
        return Err(format!(
            "unsupported ChaumPedersenProof wire version: expected {WIRE_VERSION}, got {}",
            proof_wire.version
        ));
    }

    // Build the canonical wire PartialDecryption.
    let pd = PartialDecryption {
        version: WIRE_VERSION,
        trustee_id: partial.trustee_id.clone(),
        share: share_bytes.to_vec(),
        proof: Some(proof_wire),
        contest_id: partial.contest_id.clone(),
    };
    let canonical = encode_protocol_message(&pd);

    let mut transcript = Transcript::new(TRANSCRIPT_LABEL_CHAUM_PEDERSEN);
    transcript.append_message(b"trustee_id", partial.trustee_id.as_bytes());
    transcript.append_message(b"partial_decryption", &canonical);
    let mut digest = [0u8; 32];
    transcript.challenge_bytes(b"publication_digest", &mut digest);

    Ok(TranscriptPublicationDto {
        label: "saksi.ffi.tauri.partial-decryption.v2".to_owned(),
        digest: hex_lower(&digest),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn digest_handle(label: &'static str, parts: &[String]) -> TranscriptPublicationDto {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    TranscriptPublicationDto {
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
    use super::{partial_decrypt, publish_dkg_transcript, CiphertextDto};

    #[test]
    fn tauri_partial_decrypt_returns_share() {
        let partial = partial_decrypt(
            "trustee-1".to_owned(),
            42,
            CiphertextDto {
                pad: "0e1d5b2771666dd340a8285c3d315e94f21c3b48be9c5d65352eb952541db019".to_owned(),
                data: "8af8a8933f35789af543aa4aeace1b033a03e87bb603bc77f8bb85e2b2bff92a".to_owned(),
            },
        )
        .expect("partial decrypts");

        assert_eq!(partial.trustee_id, "trustee-1");
        assert_eq!(partial.share.len(), 64);
    }

    #[test]
    fn tauri_transcript_publication_returns_digest() {
        let publication = publish_dkg_transcript("trustee-1".to_owned(), "transcript".to_owned());
        assert_eq!(publication.label, "saksi.ffi.tauri.dkg-transcript.v1");
        assert_eq!(publication.digest.len(), 64);
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;
    use saksi_protocol::{TrusteeCommitment, WIRE_VERSION};

    fn sample_ciphertext() -> CiphertextDto {
        CiphertextDto {
            pad: "0e1d5b2771666dd340a8285c3d315e94f21c3b48be9c5d65352eb952541db019".to_owned(),
            data: "8af8a8933f35789af543aa4aeace1b033a03e87bb603bc77f8bb85e2b2bff92a".to_owned(),
        }
    }

    // -- 8: partial_decrypt_v2 happy --------------------------------------

    #[test]
    fn partial_decrypt_v2_happy_proof_verifies() {
        let secret_share = Scalar::from(42u64);
        let pub_share = secret_share * basepoint();
        let secret_share_hex = hex_lower(&secret_share.to_bytes());
        let pub_share_hex = hex_lower(&compress_point(&pub_share));

        let ct = sample_ciphertext();
        let dto = partial_decrypt_v2(
            "trustee-1".to_owned(),
            "contest-1".to_owned(),
            secret_share_hex,
            pub_share_hex,
            ct.clone(),
            "election=2026|share=1".to_owned(),
        )
        .expect("ok");
        assert_eq!(dto.trustee_id, "trustee-1");
        assert_eq!(dto.share_hex.len(), 64);
        assert!(!dto.proof_bytes_hex.is_empty());

        // Reconstruct the public statement and verify the proof bytes.
        let pad = decode_point(&ct.pad).expect("decode pad");
        let share_point = decode_point(&dto.share_hex).expect("decode share");
        let proof_bytes = parse_hex(&dto.proof_bytes_hex).expect("hex");
        let proof_wire: ProtoChaumPedersenProof =
            decode_protocol_message(&proof_bytes).expect("decode proof");
        let proof = ChaumPedersenProof::from_wire(&proof_wire).expect("from_wire");
        let g = basepoint();
        proof
            .verify(&g, &pad, &pub_share, &share_point, b"election=2026|share=1")
            .expect("CP proof verifies");
    }

    // -- 9: partial_decrypt_v2 mismatched pub key -------------------------

    #[test]
    fn partial_decrypt_v2_rejects_mismatched_public_key() {
        let secret_share = Scalar::from(42u64);
        // Use a *different* scalar's public key.
        let wrong_pub_share = Scalar::from(43u64) * basepoint();
        let secret_share_hex = hex_lower(&secret_share.to_bytes());
        let pub_share_hex = hex_lower(&compress_point(&wrong_pub_share));

        let err = partial_decrypt_v2(
            "trustee-1".to_owned(),
            "contest-1".to_owned(),
            secret_share_hex,
            pub_share_hex,
            sample_ciphertext(),
            "ctx".to_owned(),
        )
        .expect_err("mismatched key must be rejected");
        assert!(err.contains("does not match"), "unexpected error: {err}");
    }

    // -- 10: publish_dkg_transcript_v2 happy + determinism ---------------

    fn sample_dkg_transcript() -> DKGTranscript {
        DKGTranscript {
            version: WIRE_VERSION,
            election_id: "election-2026".to_owned(),
            threshold: 2,
            trustee_commitments: vec![TrusteeCommitment {
                trustee_id: "trustee-1".to_owned(),
                coefficient_commitments: vec![vec![1u8; 32], vec![2u8; 32]],
            }],
            complaints: vec![],
        }
    }

    #[test]
    fn publish_dkg_transcript_v2_happy_is_deterministic() {
        let wire_bytes = encode_protocol_message(&sample_dkg_transcript());
        let wire_hex = hex_lower(&wire_bytes);

        let a = publish_dkg_transcript_v2("trustee-1".to_owned(), wire_hex.clone()).expect("ok");
        let b = publish_dkg_transcript_v2("trustee-1".to_owned(), wire_hex).expect("ok");
        assert_eq!(a.label, "saksi.ffi.tauri.dkg-transcript.v2");
        assert_eq!(a.digest.len(), 64);
        assert_eq!(a, b, "deterministic on identical inputs");
    }

    // -- 11: publish_dkg_transcript_v2 wrong version ---------------------

    #[test]
    fn publish_dkg_transcript_v2_rejects_unsupported_version() {
        let mut t = sample_dkg_transcript();
        t.version = 99;
        let wire_hex = hex_lower(&encode_protocol_message(&t));
        let err = publish_dkg_transcript_v2("trustee-1".to_owned(), wire_hex)
            .expect_err("unsupported version must be rejected");
        assert!(err.contains("99"), "unexpected error: {err}");
    }

    // -- 12: publish_partial_decryption_v2 round-trip --------------------

    #[test]
    fn publish_partial_decryption_v2_round_trip() {
        // Build a real partial_decrypt_v2 first.
        let secret_share = Scalar::from(101u64);
        let pub_share = secret_share * basepoint();
        let partial = partial_decrypt_v2(
            "trustee-7".to_owned(),
            "contest-1".to_owned(),
            hex_lower(&secret_share.to_bytes()),
            hex_lower(&compress_point(&pub_share)),
            sample_ciphertext(),
            "trustee=7".to_owned(),
        )
        .expect("partial ok");

        // Publish, get a digest.
        let pub_dto = publish_partial_decryption_v2(partial.clone()).expect("publish ok");
        assert_eq!(pub_dto.label, "saksi.ffi.tauri.partial-decryption.v2");
        assert_eq!(pub_dto.digest.len(), 64);

        // Now: decode the wire we'd have published (rebuild it the same way).
        let share_bytes = parse_32_byte_hex(&partial.share_hex).expect("hex");
        let proof_bytes = parse_hex(&partial.proof_bytes_hex).expect("hex");
        let proof_wire: ProtoChaumPedersenProof =
            decode_protocol_message(&proof_bytes).expect("decode");
        let pd = PartialDecryption {
            version: WIRE_VERSION,
            trustee_id: partial.trustee_id.clone(),
            share: share_bytes.to_vec(),
            proof: Some(proof_wire),
            contest_id: partial.contest_id.clone(),
        };
        let canonical = encode_protocol_message(&pd);
        let decoded: PartialDecryption = decode_protocol_message(&canonical).expect("re-decodes");
        assert_eq!(decoded.trustee_id, "trustee-7");
        assert_eq!(decoded.share, share_bytes.to_vec());
        assert!(decoded.proof.is_some());

        // Deterministic: republishing identical bytes gives the same digest.
        let pub_dto2 = publish_partial_decryption_v2(partial).expect("publish ok");
        assert_eq!(pub_dto, pub_dto2);
    }
}
