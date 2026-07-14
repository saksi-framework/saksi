//! ElectionGuard interop sanity check (thesis Phase 3).
//!
//! **Sanity/interop check, NOT a conformance proof.** ElectionGuard uses integer
//! ElGamal modulo a large prime; Saksi uses ristretto255 elliptic-curve ElGamal.
//! Ciphertext bytes, nonces, and proof systems differ, so byte-level vectors are
//! not comparable. What this pins is the plaintext **tally semantics** both
//! exponential-ElGamal voting schemes must agree on: encrypt each `{0,1}`
//! selection, homomorphically add the ciphertexts, decrypt, and recover the same
//! per-selection totals ElectionGuard's model produces.
//!
//! The pinned scenarios live in
//! `saksi-protocol/test-vectors/eg-interop-v1.json` (see its `_source` /
//! `_framing`).

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use serde_json::Value;

    use crate::elgamal::{decrypt, encrypt, Ciphertext, Plaintext, SecretKey};

    const VECTORS: &str = include_str!("../../saksi-protocol/test-vectors/eg-interop-v1.json");

    // A deterministic per-(ballot, candidate) ElGamal nonce so the test needs no
    // RNG. The value is irrelevant to correctness (re-randomization does not
    // change the plaintext); it only needs to be a valid scalar.
    fn nonce(ballot: usize, candidate: usize) -> Scalar {
        Scalar::from((ballot as u64) * 1_000 + (candidate as u64) + 1)
    }

    #[test]
    fn saksi_reproduces_electionguard_model_tallies() {
        let doc: Value = serde_json::from_str(VECTORS).expect("eg-interop vectors parse");
        let scenarios = doc["scenarios"].as_array().expect("scenarios array");
        assert!(!scenarios.is_empty(), "at least one pinned scenario");

        // A single decryption authority is enough to validate the additive-
        // homomorphic tally property (the threshold variant is exercised
        // end-to-end by saksi-auditor).
        let secret_key = SecretKey::from_scalar(Scalar::from(0xE1EC_2026u64));
        let public_key = secret_key.public_key();

        for scenario in scenarios {
            let name = scenario["name"].as_str().unwrap_or("?");
            let candidates = scenario["candidates"].as_u64().expect("candidates") as usize;
            let ballots = scenario["ballots"].as_array().expect("ballots");
            let expected: Vec<u64> = scenario["expected_tally"]
                .as_array()
                .expect("expected_tally")
                .iter()
                .map(|v| v.as_u64().expect("tally int"))
                .collect();
            assert_eq!(
                expected.len(),
                candidates,
                "scenario {name}: expected_tally width must equal candidate count"
            );

            // Homomorphic accumulator per candidate slot, seeded with an
            // encryption of 0.
            let mut acc: Vec<Ciphertext> = (0..candidates)
                .map(|c| {
                    encrypt(
                        &public_key,
                        Plaintext::from_small_integer(0),
                        nonce(900_000, c),
                    )
                })
                .collect();
            // Independent plaintext recount to cross-check the pinned expectation.
            let mut plaintext_sum = vec![0u64; candidates];

            for (b, ballot) in ballots.iter().enumerate() {
                let selections = ballot.as_array().expect("ballot row");
                assert_eq!(
                    selections.len(),
                    candidates,
                    "scenario {name}: ballot {b} width mismatch"
                );
                let mut chosen = 0u64;
                for (c, sel) in selections.iter().enumerate() {
                    let s = sel.as_u64().expect("selection int");
                    assert!(s <= 1, "scenario {name}: selection must be 0 or 1");
                    chosen += s;
                    plaintext_sum[c] += s;
                    acc[c] += encrypt(&public_key, Plaintext::from_small_integer(s), nonce(b, c));
                }
                // ElectionGuard single-choice contest: exactly one selection set.
                assert_eq!(
                    chosen, 1,
                    "scenario {name}: ballot {b} must be a valid single choice"
                );
            }

            for c in 0..candidates {
                assert_eq!(
                    plaintext_sum[c], expected[c],
                    "scenario {name}: pinned expected_tally disagrees with the plaintext recount at candidate {c}"
                );
                let decrypted = decrypt(&secret_key, &acc[c]);
                assert_eq!(
                    decrypted,
                    Plaintext::from_small_integer(expected[c]),
                    "scenario {name}: homomorphic decrypt at candidate {c} != ElectionGuard-model tally {}",
                    expected[c]
                );
            }
        }
    }
}
