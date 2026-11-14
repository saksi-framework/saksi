//! # saksi-live
//!
//! The party-side steps of a live election, as I/O-free functions whose
//! inputs and outputs are the hex/JSON wire format of `docs/live/wire-format.md`:
//!
//! - [`election`]: election parameters, the joint key read from a published
//!   DKG transcript, the tracking code.
//! - [`issuance`]: the voter's three and the issuer's two blind-issuance steps.
//! - [`ballot`]: one position's ballot record (presentation, ElGamal, CDS,
//!   selection proof).
//! - [`benaloh`]: the voter's Benaloh challenge over a ballot built with
//!   [`ballot::build_ballot_with_opening`].
//! - [`dkg`]: one trustee's deal and receive, with shares masked for the
//!   relay.
//!
//! Everything here compiles for `wasm32-unknown-unknown` (the phone's
//! WebAssembly calls [`issuance`] and [`ballot`] directly); the consumer turns
//! on `getrandom/js`. The `saksi-demo live` CLI adds the file handling.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ballot;
pub mod benaloh;
pub mod codec;
pub mod dkg;
pub mod election;
pub mod issuance;

/// The version of the live wire format (`docs/live/wire-format.md`) this
/// build speaks. The phone shows and logs it with the crate version.
pub const WIRE_FORMAT: &str = "saksi-live-wire-v1";

#[cfg(test)]
pub(crate) mod test_support {
    //! A small election for the ballot and Benaloh tests: an issuer, two
    //! positions of three candidates, a 5-dealer transcript with threshold 3
    //! (random commitments; only their shape and the joint key matter here)
    //! and one issued credential.

    use curve25519_dalek::ristretto::RistrettoPoint;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use saksi_protocol::{DKGTranscript, TrusteeCommitment, WIRE_VERSION};
    use sha2::{Digest, Sha256};

    use crate::{ballot::BallotRequest, codec, election, issuance};

    /// A deterministic test RNG: SHA-256(seed || counter) blocks. For tests
    /// that need the same random stream twice; never for real keys.
    pub struct StreamRng {
        seed: [u8; 32],
        counter: u64,
        buf: Vec<u8>,
    }

    impl StreamRng {
        pub fn new(seed: u8) -> Self {
            Self {
                seed: [seed; 32],
                counter: 0,
                buf: Vec::new(),
            }
        }
    }

    impl RngCore for StreamRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                if self.buf.is_empty() {
                    let mut h = Sha256::new();
                    h.update(self.seed);
                    h.update(self.counter.to_le_bytes());
                    self.counter += 1;
                    self.buf = h.finalize().to_vec();
                }
                *byte = self.buf.remove(0);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for StreamRng {}

    pub struct TestElection {
        pub params: String,
        pub dkg: String,
        pub credential: issuance::CredentialParts,
    }

    impl TestElection {
        pub fn request(&self, position: &str, choice: usize) -> BallotRequest {
            BallotRequest {
                params: self.params.clone(),
                dkg: self.dkg.clone(),
                credential: self.credential.clone(),
                position_id: position.into(),
                choice,
            }
        }
    }

    pub fn election(election_id: &str) -> TestElection {
        let (issuer_secret, issuer) = issuance::issuer_keygen(&mut OsRng);
        let pk_hex = codec::point_hex(issuer.as_point());
        let params = election::election_params(&election::ParamsRequest {
            election_id: election_id.into(),
            positions: vec![
                election::Position {
                    id: "president".into(),
                    candidates: vec!["alice".into(), "bob".into(), "carol".into()],
                },
                election::Position {
                    id: "secretary".into(),
                    candidates: vec!["dan".into(), "eve".into(), "fay".into()],
                },
            ],
            trustees: 5,
            threshold: 3,
            issuer_public_key: pk_hex.clone(),
        })
        .unwrap();
        let transcript = DKGTranscript {
            version: WIRE_VERSION,
            election_id: election_id.into(),
            threshold: 3,
            trustee_commitments: (1..=5)
                .map(|id| TrusteeCommitment {
                    trustee_id: id.to_string(),
                    coefficient_commitments: (0..3)
                        .map(|_| {
                            RistrettoPoint::random(&mut OsRng)
                                .compress()
                                .to_bytes()
                                .to_vec()
                        })
                        .collect(),
                })
                .collect(),
            complaints: Vec::new(),
        };
        // Issuance through the hex steps.
        let begin = issuance::voter_begin(&mut OsRng);
        let (r, k) =
            issuance::issuer_presign(&issuer_secret, &begin.blinded_commitment, &mut OsRng)
                .unwrap();
        let blind = issuance::voter_blind(
            &issuance::BlindRequestJson {
                state: begin.state.clone(),
                r,
                issuer_public_key: pk_hex.clone(),
            },
            &mut OsRng,
        )
        .unwrap();
        let s_iss = issuance::issuer_sign(&issuer_secret, k, &blind.e_prime).unwrap();
        let credential = issuance::voter_finalize(&issuance::FinalizeRequest {
            state: blind.state.clone(),
            s_iss,
            issuer_public_key: pk_hex,
        })
        .unwrap()
        .credential
        .clone();
        TestElection {
            params: params.params,
            dkg: codec::message_hex(&transcript),
            credential,
        }
    }
}
