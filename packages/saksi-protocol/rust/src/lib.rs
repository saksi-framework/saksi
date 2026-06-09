//! # saksi-protocol (Rust)
//!
//! Canonical BalotaChain and Saksi wire types. Schema lives in
//! [`../proto/tala/protocol/v1/wire.proto`](../../proto/tala/protocol/v1/wire.proto)
//! and is compiled into Rust types via `prost` (see [`build.rs`](../build.rs)).
//!
//! The Go mirror under [`../go`](../../go/) compiles the same `.proto` with
//! `protoc-gen-go`. Both sides must serialize identically; the
//! `test-vectors/` directory contains golden fixtures that both implementations
//! check against.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use prost::Message;
use sha2::{Digest, Sha256};

/// Generated Protocol Buffers types for the v1 wire format.
#[allow(missing_docs)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/tala.protocol.v1.rs"));
}

pub use v1::{
    Ballot, CdsProof as CDSProof, CdsProofBranch as CDSProofBranch, ChaumPedersenProof, Ciphertext,
    CredentialPresentation, DkgComplaint as DKGComplaint, DkgTranscript as DKGTranscript,
    ElectionParameters, Nullifier, PartialDecryption, PedersenCommitment, TallyResult,
    TrusteeCommitment,
};

/// The current wire-format version. Every protobuf message that crosses the
/// trust boundary carries a `version` field initialized to this constant.
pub const WIRE_VERSION: u32 = 1;

/// Errors raised by serialization helpers in this crate.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The provided byte buffer could not be decoded as the requested protobuf type.
    #[error("protobuf decode failed: {0}")]
    Decode(#[from] prost::DecodeError),
}

/// Serialize any protobuf message generated from `wire.proto` to its canonical bytes.
pub fn encode<M>(message: &M) -> Vec<u8>
where
    M: Message,
{
    message.encode_to_vec()
}

/// Deserialize canonical bytes into the requested protobuf type.
pub fn decode<M>(bytes: &[u8]) -> Result<M, ProtocolError>
where
    M: Message + Default,
{
    Ok(M::decode(bytes)?)
}

/// Compute a domain-separated SHA-256 hash over a list of byte slices.
///
/// The hash is bound to `b"tala-protocol-v1"` followed by the caller-supplied
/// domain label and length-prefixed input parts. This is the canonical hash
/// helper used wherever a Saksi wire type needs to be bound to a transcript
/// without leaking through ambiguous concatenation.
pub fn domain_hash(domain: &'static [u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"tala-protocol-v1");
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);

    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ballot() -> Ballot {
        Ballot {
            version: WIRE_VERSION,
            election_id: "election-2026".to_owned(),
            voter_credential_commitment: vec![1, 2, 3],
            ciphertexts: vec![Ciphertext {
                version: WIRE_VERSION,
                pad: vec![4; 32],
                data: vec![5; 32],
            }],
            well_formedness_proofs: vec![CDSProof {
                version: WIRE_VERSION,
                branches: vec![CDSProofBranch {
                    commitment_a: vec![6; 32],
                    commitment_b: vec![7; 32],
                    challenge: vec![8; 32],
                    response: vec![9; 32],
                }],
            }],
            credential_presentation: Some(CredentialPresentation {
                version: WIRE_VERSION,
                credential_commitment: vec![10; 32],
                issuer_public_key: vec![11; 32],
                presentation_proof: vec![12; 64],
                nullifier: Some(Nullifier {
                    version: WIRE_VERSION,
                    value: vec![13; 32],
                }),
            }),
        }
    }

    #[test]
    fn ballot_round_trips() {
        let ballot = sample_ballot();
        let bytes = encode(&ballot);
        let decoded: Ballot = decode(&bytes).expect("ballot should decode");
        assert_eq!(decoded, ballot);
    }

    #[test]
    fn domain_hash_is_domain_separated() {
        let first = domain_hash(b"ballot", &[b"abc"]);
        let second = domain_hash(b"credential", &[b"abc"]);
        assert_ne!(first, second);
    }

    #[test]
    fn ballot_test_vector_is_stable() {
        let bytes = encode(&sample_ballot());
        assert_eq!(
            hex_lower(&bytes),
            include_str!("../../test-vectors/ballot-v1.hex").trim()
        );
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
}
