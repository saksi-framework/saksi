//! Sum-to-one selection proof for one ballot record.
//!
//! A ballot record carries one ElGamal ciphertext `(A_k, B_k)` per candidate
//! of its position, each proved to encrypt 0 or 1 by a CDS OR-proof. Those
//! proofs alone let a voter mark two candidates (or none). This module proves
//! the ciphertexts encrypt exactly one selection in total:
//!
//! - `A = Σ A_k` and `B = Σ B_k − G`, so `(A, B)` encrypts `m − 1` where `m`
//!   is the number of selections;
//! - with `R = Σ r_k`, an honest record has `A = R·G` and `B = R·Y`;
//! - a [`ChaumPedersenProof`] over bases `(G, Y)` and statement `(A, B)` shows
//!   `log_G(A) = log_Y(B)`, which holds only when `m = 1`.
//!
//! The Fiat-Shamir context is [`SELECTION_CONTEXT_LABEL`] followed by
//! `binding_context(election_id, position_id, nullifier)` (the CDS
//! length-prefix style). The Go chaincode verifier
//! (`saksi-bulletin/chaincode/selectionverify`) mirrors this byte for byte;
//! the golden vector `saksi-protocol/test-vectors/selection-proof-v1.hex` pins
//! the agreement.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand_core::{CryptoRng, RngCore};

use crate::{
    elgamal::{Ciphertext, PublicKey},
    group::basepoint,
    nizk::{cds::binding_context, chaum_pedersen::ChaumPedersenProof},
    CryptoResult,
};

/// Domain label that prefixes the selection proof's Fiat-Shamir context.
pub const SELECTION_CONTEXT_LABEL: &[u8] = b"saksi.ballot.selection.v1";

/// `SELECTION_CONTEXT_LABEL || binding_context(election_id, position_id, nullifier)`.
pub fn selection_context(election_id: &[u8], position_id: &[u8], nullifier: &[u8]) -> Vec<u8> {
    let mut ctx = SELECTION_CONTEXT_LABEL.to_vec();
    ctx.extend_from_slice(&binding_context(election_id, position_id, nullifier));
    ctx
}

/// The statement `(Σ A_k, Σ B_k − G)`.
fn statement(ciphertexts: &[Ciphertext]) -> (RistrettoPoint, RistrettoPoint) {
    let (a, b) = ciphertexts.iter().fold(
        (RistrettoPoint::identity(), RistrettoPoint::identity()),
        |(a, b), ct| (a + ct.pad, b + ct.data),
    );
    (a, b - basepoint())
}

/// Prove that `ciphertexts` encrypt exactly one selection. `randomness_sum` is
/// `Σ r_k` over the encryption randomness. The caller must pass an honest
/// one-hot record; the routine does not re-check it (a dishonest record yields
/// a proof that fails [`verify_selection`]).
pub fn prove_selection(
    public_key: &PublicKey,
    ciphertexts: &[Ciphertext],
    randomness_sum: &Scalar,
    context: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> ChaumPedersenProof {
    let (a, b) = statement(ciphertexts);
    ChaumPedersenProof::prove(
        &basepoint(),
        public_key.as_point(),
        &a,
        &b,
        randomness_sum,
        context,
        rng,
    )
}

/// Verify a selection proof over `ciphertexts` under `public_key` and `context`.
pub fn verify_selection(
    proof: &ChaumPedersenProof,
    public_key: &PublicKey,
    ciphertexts: &[Ciphertext],
    context: &[u8],
) -> CryptoResult<()> {
    let (a, b) = statement(ciphertexts);
    proof.verify(&basepoint(), public_key.as_point(), &a, &b, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::OsRng;

    use crate::{
        elgamal::{encrypt, Plaintext},
        group::compress_point,
        nizk::cds::CDSProof,
        CryptoError,
    };

    /// Encrypts `choices` under a random key; returns the key, ciphertexts and `Σ r_k`.
    fn record(choices: &[u64]) -> (PublicKey, Vec<Ciphertext>, Scalar) {
        let mut rng = OsRng;
        let pk = PublicKey::from_point(Scalar::random(&mut rng) * basepoint());
        let mut sum = Scalar::ZERO;
        let cts = choices
            .iter()
            .map(|&m| {
                let r = Scalar::random(&mut rng);
                sum += r;
                encrypt(&pk, Plaintext::from_small_integer(m), r)
            })
            .collect();
        (pk, cts, sum)
    }

    fn ctx() -> Vec<u8> {
        selection_context(b"election-2026", b"president", &[7u8; 32])
    }

    #[test]
    fn one_hot_verifies() {
        let (pk, cts, r) = record(&[0, 1, 0, 0]);
        let proof = prove_selection(&pk, &cts, &r, &ctx(), &mut OsRng);
        verify_selection(&proof, &pk, &cts, &ctx()).expect("one-hot verifies");
    }

    #[test]
    fn two_selections_fail() {
        let (pk, cts, r) = record(&[1, 1, 0]);
        let proof = prove_selection(&pk, &cts, &r, &ctx(), &mut OsRng);
        assert_eq!(
            verify_selection(&proof, &pk, &cts, &ctx()),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn no_selection_fails() {
        let (pk, cts, r) = record(&[0, 0, 0]);
        let proof = prove_selection(&pk, &cts, &r, &ctx(), &mut OsRng);
        assert_eq!(
            verify_selection(&proof, &pk, &cts, &ctx()),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn wrong_context_fails() {
        let (pk, cts, r) = record(&[0, 0, 1]);
        let proof = prove_selection(&pk, &cts, &r, &ctx(), &mut OsRng);
        let other = selection_context(b"election-2026", b"vice-president", &[7u8; 32]);
        assert_eq!(
            verify_selection(&proof, &pk, &cts, &other),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn context_is_label_then_length_prefixed_fields() {
        let got = selection_context(b"e", b"pp", &[9u8; 2]);
        let mut want = b"saksi.ballot.selection.v1".to_vec();
        for part in [&b"e"[..], b"pp", &[9, 9]] {
            want.extend_from_slice(&(part.len() as u64).to_be_bytes());
            want.extend_from_slice(part);
        }
        assert_eq!(got, want);
    }

    /// Deterministic SplitMix64 RNG so the golden vector is reproducible.
    struct CountRng(u64);
    impl RngCore for CountRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for CountRng {}

    /// Cross-language golden vector for on-chain selection-proof verification.
    /// The Go chaincode (`selectionverify`, and the SubmitBallot tests) must
    /// accept the honest record and refuse the overvote. Layout (length
    /// prefixes u64 big-endian):
    ///   len||election_id | len||position_id | nullifier[32] | pk[32] | n[1] |
    ///   n × honest (pad[32] data[32] 2 × CDS branch[128]) |
    ///   selection proof (commitment_a commitment_b challenge response, 32 each) |
    ///   n × overvote (pad[32] data[32] 2 × CDS branch[128])
    /// Contest k of the position is `"<position_id>/<k>"`; the honest record
    /// selects candidate 1, the overvote selects every candidate. CDS contexts
    /// are `binding_context(election_id, contest_id, nullifier)`.
    ///
    /// Regenerate with `SAKSI_WRITE_VECTORS=1 cargo test -p saksi-crypto
    /// selection_golden_vector`, then rerun the Go tests.
    #[test]
    fn selection_golden_vector() {
        let hex = golden_vector(0x5341_4b53_495f_5345, b"p0", 43, true); // "SAKSI_SE"
        pin(&hex, "selection-proof-v1.hex");
    }

    /// The second-vote exploit vector: a fully valid **whole-ballot record**
    /// (empty position_id) over the same election and contests `p0/0`, `p0/1`
    /// as the selection vector. Its nullifier (44·G) stands for the one a
    /// presentation for position "" derives, distinct from the selection
    /// vector's per-position nullifier (43·G); its CDS proofs are bound to it;
    /// its selection proof (position "") shows the sum over both contests is 1.
    /// Same layout as the selection vector, without the overvote record. The
    /// Go chaincode test loads it to replay the exploit and must refuse it at
    /// `shape` on an issuer-bound election.
    ///
    /// Regenerate with `SAKSI_WRITE_VECTORS=1 cargo test -p saksi-crypto
    /// whole_ballot_record_vector`, then rerun the Go tests.
    #[test]
    fn whole_ballot_record_vector() {
        let hex = golden_vector(0x5341_4b53_495f_5742, b"", 44, false); // "SAKSI_WB"
        pin(&hex, "whole-ballot-record-v1.hex");
    }

    /// Builds a golden vector for election "election-2026", pk = 7·G,
    /// nullifier = `nullifier_k`·G, contests `p0/0`, `p0/1`: the header, an
    /// honest record selecting candidate 1, its selection proof bound to
    /// `position_id`, and, with `overvote`, an all-ones record.
    fn golden_vector(seed: u64, position_id: &[u8], nullifier_k: u64, overvote: bool) -> String {
        let mut rng = CountRng(seed);
        let election_id: &[u8] = b"election-2026";
        let pk = PublicKey::from_point(Scalar::from(7u64) * basepoint());
        let nullifier = compress_point(&(Scalar::from(nullifier_k) * basepoint()));
        let n = 2usize;
        let choice_set = [Scalar::ZERO, Scalar::ONE];

        let encode = |choices: &[u64], v: &mut Vec<u8>, rng: &mut CountRng| {
            let mut cts = Vec::new();
            let mut sum = Scalar::ZERO;
            for (k, &m) in choices.iter().enumerate() {
                let r = Scalar::from(11u64 + k as u64 + 10 * m);
                sum += r;
                let ct = encrypt(&pk, Plaintext::from_small_integer(m), r);
                let contest = format!("p0/{k}");
                let cds_ctx = binding_context(election_id, contest.as_bytes(), &nullifier);
                let cds = CDSProof::prove(&pk, &ct, &choice_set, m as usize, &r, &cds_ctx, rng)
                    .expect("CDS prove");
                let (pad, data) = ct.to_compressed_bytes();
                v.extend_from_slice(&pad);
                v.extend_from_slice(&data);
                for b in cds.to_wire().branches {
                    for field in [b.commitment_a, b.commitment_b, b.challenge, b.response] {
                        v.extend_from_slice(&field);
                    }
                }
                cts.push(ct);
            }
            (cts, sum)
        };

        let mut v: Vec<u8> = Vec::new();
        for part in [election_id, position_id] {
            v.extend_from_slice(&(part.len() as u64).to_be_bytes());
            v.extend_from_slice(part);
        }
        v.extend_from_slice(&nullifier);
        v.extend_from_slice(&pk.to_compressed_bytes());
        v.push(n as u8);

        let ctx = selection_context(election_id, position_id, &nullifier);
        let (cts, sum) = encode(&[0, 1], &mut v, &mut rng);
        let proof = prove_selection(&pk, &cts, &sum, &ctx, &mut rng);
        verify_selection(&proof, &pk, &cts, &ctx).expect("honest verifies");
        let wire = proof.to_wire();
        for field in [
            &wire.commitment_a,
            &wire.commitment_b,
            &wire.challenge,
            &wire.response,
        ] {
            v.extend_from_slice(field);
        }
        if overvote {
            let (over, _) = encode(&[1, 1], &mut v, &mut rng);
            assert!(verify_selection(&proof, &pk, &over, &ctx).is_err());
        }
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Checks `hex` against the pinned vector `file` in saksi-protocol's
    /// test-vectors, writing it first under `SAKSI_WRITE_VECTORS`.
    fn pin(hex: &str, file: &str) {
        let path = format!(
            "{}/../saksi-protocol/test-vectors/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var_os("SAKSI_WRITE_VECTORS").is_some() {
            std::fs::write(&path, format!("{hex}\n")).expect("write vector");
        }
        let pinned = std::fs::read_to_string(&path).expect("read pinned vector");
        assert_eq!(
            hex,
            pinned.trim(),
            "{file} drifted; regenerate and rerun the Go tests"
        );
    }
}
