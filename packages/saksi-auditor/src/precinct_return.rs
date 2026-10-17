//! Precinct return: the signed, encrypted per-precinct result a precinct
//! transmits to the national canvass.
//!
//! A return binds a precinct's ledger read-back (record count, [`ledger_digest`],
//! per-contest homomorphic aggregate `(Σc1, Σc2)`) to its election id, its
//! precinct id and the chain state at close (block number and tip hash), under a
//! per-precinct authority key. It is not the trustee-signed "election return"
//! (the decrypted tally); it carries ciphertexts only.
//!
//! The signature is the existing ristretto255 Schnorr proof of knowledge of the
//! authority secret (`saksi_crypto::nizk::schnorr::SchnorrProof`, base `G`,
//! statement the authority public key) with [`PrecinctReturn::message`] as the
//! transcript context. The Go verifier `sigverify.ReturnSigMessage` /
//! `VerifyReturnSig` mirrors the message byte for byte; the golden vector
//! `saksi-protocol/test-vectors/er-sig-v1.hex` pins the agreement.
//!
//! [`ledger_digest`]: crate::ledger::ledger_digest

use std::path::Path;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use saksi_crypto::group::{basepoint, point_from_compressed, scalar_from_canonical_bytes};
use saksi_crypto::nizk::schnorr::SchnorrProof;
use serde::{Deserialize, Serialize};

/// Domain separator that starts every return signing message.
pub const RETURN_SIG_DOMAIN: &[u8] = b"saksi.er.sig.v1";

/// Default file name of a written return.
pub const RETURN_FILE: &str = "return.json";

/// One contest's aggregate in a [`PrecinctReturn`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnContest {
    /// Position-qualified contest id (`president/cand0`).
    pub contest_id: String,
    /// `Σc1` (sum of pads), compressed point.
    #[serde(with = "hex_bytes")]
    pub sum_c1: [u8; 32],
    /// `Σc2` (sum of data components), compressed point.
    #[serde(with = "hex_bytes")]
    pub sum_c2: [u8; 32],
}

/// A signed precinct return. JSON fields are hex for byte arrays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecinctReturn {
    /// The precinct's election id (`<base>-pNN`).
    pub election_id: String,
    /// The precinct id (`pNN`), as in `registry.json`.
    pub precinct_id: String,
    /// The channel height as reported by Fabric `ChainInfo` after the
    /// precinct's tally was published and its ledger dumped. The verifier
    /// compares it with `close.json`, written by the driver at that same moment.
    pub close_block: u64,
    /// Hash of that block.
    #[serde(with = "hex_bytes")]
    pub close_tip_hash: [u8; 32],
    /// Records in the ledger read-back.
    pub record_count: u64,
    /// `ledger_digest` of the read-back, in the order the chain served it.
    #[serde(with = "hex_bytes")]
    pub ledger_digest: [u8; 32],
    /// Per-contest aggregates, in `contest_ids` order.
    pub contests: Vec<ReturnContest>,
    /// Schnorr proof (commitment ‖ response) over [`Self::message`].
    #[serde(with = "hex_bytes")]
    pub signature: [u8; 64],
}

impl PrecinctReturn {
    /// The exact bytes signed: [`RETURN_SIG_DOMAIN`], then every field except
    /// the signature, in declaration order. Each variable-length field (the two
    /// ids, each contest id) is preceded by its length as a u32 little-endian;
    /// integers are u64 little-endian; 32-byte fields are raw. The contests are
    /// a u32 LE count followed by, per contest, `len ‖ contest_id ‖ Σc1 ‖ Σc2`.
    pub fn message(&self) -> Vec<u8> {
        fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
            let len = u32::try_from(bytes.len()).expect("return field under 4 GiB");
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(160 + self.contests.len() * 100);
        out.extend_from_slice(RETURN_SIG_DOMAIN);
        lp(&mut out, self.election_id.as_bytes());
        lp(&mut out, self.precinct_id.as_bytes());
        out.extend_from_slice(&self.close_block.to_le_bytes());
        out.extend_from_slice(&self.close_tip_hash);
        out.extend_from_slice(&self.record_count.to_le_bytes());
        out.extend_from_slice(&self.ledger_digest);
        let count = u32::try_from(self.contests.len()).expect("contest count under 2^32");
        out.extend_from_slice(&count.to_le_bytes());
        for c in &self.contests {
            lp(&mut out, c.contest_id.as_bytes());
            out.extend_from_slice(&c.sum_c1);
            out.extend_from_slice(&c.sum_c2);
        }
        out
    }

    /// Signs [`Self::message`] with the authority `secret`, replacing
    /// `signature`.
    pub fn sign(&mut self, secret: &Scalar, rng: &mut (impl RngCore + CryptoRng)) {
        let g = basepoint();
        let proof = SchnorrProof::prove(&g, &(secret * g), secret, &self.message(), rng);
        self.signature = proof.to_bytes();
    }

    /// Verifies `signature` over [`Self::message`] under the compressed
    /// authority public key.
    pub fn verify(&self, pubkey: &[u8; 32]) -> Result<(), String> {
        let statement =
            point_from_compressed(*pubkey).map_err(|_| "public key is not a valid point")?;
        let proof = SchnorrProof::from_bytes(&self.signature)
            .map_err(|_| "signature is not a canonical Schnorr proof")?;
        proof
            .verify(&basepoint(), &statement, &self.message())
            .map_err(|_| "signature does not verify under this public key".to_string())
    }
}

/// Reads an `authority.key` file (hex of a canonical 32-byte scalar).
pub fn read_authority_key(path: &Path) -> Result<Scalar, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .map_err(|e| format!("{}: not hex: {e}", path.display()))?
        .try_into()
        .map_err(|_| format!("{}: not 32 bytes", path.display()))?;
    scalar_from_canonical_bytes(bytes)
        .map_err(|_| format!("{}: not a canonical scalar", path.display()))
}

/// Parses 32 bytes of hex (a public key or a block hash).
pub fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim())
        .map_err(|e| format!("{what}: not hex: {e}"))?
        .try_into()
        .map_err(|_| format!("{what}: not 32 bytes"))
}

/// Builds and signs the return for the precinct run folder `precinct_dir`
/// (election id from its `header.json`; precinct id = the id's last `-pNN`
/// segment) from the ledger read-back `ledger_file`. Record count, digest and
/// aggregates are recomputed from the file. Returns the signed return and the
/// number of records that verified (the ones summed).
pub fn sign_return(
    precinct_dir: &Path,
    ledger_file: &Path,
    close_block: u64,
    close_tip_hash: [u8; 32],
    secret: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(PrecinctReturn, u64), String> {
    let header = crate::stream::read_header(precinct_dir)?;
    let precinct_id = header
        .election_id
        .rsplit_once('-')
        .map(|(_, p)| p)
        .filter(|p| p.len() > 1 && p.starts_with('p') && p[1..].bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            format!(
                "election id {:?} has no -pNN precinct suffix (not a precinct folder)",
                header.election_id
            )
        })?
        .to_string();
    let sums = crate::ledger::verified_sums(
        precinct_dir,
        crate::stream::BallotLines::open_file(ledger_file)?,
    )?;
    let mut ret = PrecinctReturn {
        election_id: header.election_id,
        precinct_id,
        close_block,
        close_tip_hash,
        record_count: sums.record_count,
        ledger_digest: sums.ledger_digest,
        contests: sums
            .contests
            .into_iter()
            .map(|(contest_id, sum_c1, sum_c2)| ReturnContest {
                contest_id,
                sum_c1,
                sum_c2,
            })
            .collect(),
        signature: [0; 64],
    };
    ret.sign(secret, rng);
    Ok((ret, sums.verified))
}

/// Hex (de)serialisation of fixed-size byte arrays.
mod hex_bytes {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(b: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|v: Vec<u8>| D::Error::custom(format!("expected {N} bytes, got {}", v.len())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use saksi_crypto::group::compress_point;
    use std::path::PathBuf;

    /// SplitMix64 as an `RngCore`, so the golden vector's signature is
    /// byte-stable. Vector-only; production signing uses `OsRng`.
    struct SplitMix64(u64);

    impl RngCore for SplitMix64 {
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

    impl CryptoRng for SplitMix64 {}

    fn pt(k: u64) -> [u8; 32] {
        compress_point(&(Scalar::from(k) * basepoint()))
    }

    fn vector_key() -> Scalar {
        Scalar::from(0x5a6b_7c8d_9e0f_1a2bu64)
    }

    fn pubkey(secret: &Scalar) -> [u8; 32] {
        compress_point(&(secret * basepoint()))
    }

    /// The fixed two-contest return the golden vector signs.
    fn vector_return() -> PrecinctReturn {
        let mut r = PrecinctReturn {
            election_id: "election-2026-p03".into(),
            precinct_id: "p03".into(),
            close_block: 4242,
            close_tip_hash: [0xab; 32],
            record_count: 20,
            ledger_digest: [0x11; 32],
            contests: vec![
                ReturnContest {
                    contest_id: "president/cand0".into(),
                    sum_c1: pt(3),
                    sum_c2: pt(5),
                },
                ReturnContest {
                    contest_id: "president/cand1".into(),
                    sum_c1: pt(7),
                    sum_c2: pt(11),
                },
            ],
            signature: [0; 64],
        };
        r.sign(&vector_key(), &mut SplitMix64(0x0e75_1601));
        r
    }

    /// Hand-assembled bytes, so an encoding change cannot slip through by
    /// regenerating the vector.
    #[test]
    fn message_layout_is_domain_then_length_prefixed_fields() {
        let r = PrecinctReturn {
            election_id: "e1".into(),
            precinct_id: "p1".into(),
            close_block: 258,
            close_tip_hash: [0xaa; 32],
            record_count: 3,
            ledger_digest: [0xbb; 32],
            contests: vec![ReturnContest {
                contest_id: "c".into(),
                sum_c1: [0xcc; 32],
                sum_c2: [0xdd; 32],
            }],
            signature: [0; 64],
        };
        let expected = [
            hex::encode(b"saksi.er.sig.v1"),
            "020000006531".into(),     // len 2, "e1"
            "020000007031".into(),     // len 2, "p1"
            "0201000000000000".into(), // close_block 258 LE
            "aa".repeat(32),
            "0300000000000000".into(), // record_count 3 LE
            "bb".repeat(32),
            "01000000".into(),   // one contest
            "0100000063".into(), // len 1, "c"
            "cc".repeat(32),
            "dd".repeat(32),
        ]
        .concat();
        assert_eq!(hex::encode(r.message()), expected);
    }

    #[test]
    fn round_trip_through_json_verifies() {
        let r = vector_return();
        let pk = pubkey(&vector_key());
        r.verify(&pk).expect("signed return verifies");
        let json = serde_json::to_string(&r).unwrap();
        let back: PrecinctReturn = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        back.verify(&pk).expect("verifies after JSON round trip");
        // OsRng signing verifies too.
        let mut s = r.clone();
        s.sign(&vector_key(), &mut rand_core::OsRng);
        s.verify(&pk).expect("OsRng signature verifies");
    }

    /// T9, T12, T14, T21 and a moved close reference: each must fail.
    #[test]
    fn mutations_fail_verification() {
        let r = vector_return();
        let pk = pubkey(&vector_key());
        type Mutation = Box<dyn Fn(&mut PrecinctReturn)>;
        let cases: Vec<(&str, Mutation)> = vec![
            (
                "T9 aggregate byte flipped",
                Box::new(|r| r.contests[1].sum_c2[0] ^= 1),
            ),
            (
                "T12 precinct relabeled",
                Box::new(|r| r.precinct_id = "p04".into()),
            ),
            (
                "T14 election id changed",
                Box::new(|r| r.election_id = "election-2025-p03".into()),
            ),
            ("close block changed", Box::new(|r| r.close_block += 1)),
            ("tip hash changed", Box::new(|r| r.close_tip_hash[31] ^= 1)),
            ("record count changed", Box::new(|r| r.record_count -= 1)),
            ("digest changed", Box::new(|r| r.ledger_digest[0] ^= 1)),
            (
                "contest dropped",
                Box::new(|r| {
                    r.contests.pop();
                }),
            ),
            ("contests swapped", Box::new(|r| r.contests.swap(0, 1))),
        ];
        for (name, mutate) in cases {
            let mut m = r.clone();
            mutate(&mut m);
            assert!(m.verify(&pk).is_err(), "{name} must fail verification");
        }
        // T21: a well-formed signature by another key (a trustee's, say).
        let mut other = r.clone();
        other.sign(&Scalar::from(99u64), &mut rand_core::OsRng);
        assert!(other.verify(&pk).is_err(), "T21 other key must fail");
        assert!(other.verify(&pubkey(&Scalar::from(99u64))).is_ok());
    }

    fn vector_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../saksi-protocol/test-vectors/er-sig-v1.hex")
    }

    /// Cross-language golden vector, one item per line:
    ///
    /// ```text
    /// 1  authority secret key hex (vector only)
    /// 2  authority public key hex (compressed x·G)
    /// 3  the signed return as one-line JSON (the return.json format)
    /// 4  the signing message hex
    /// ```
    ///
    /// The Go test (`sigverify/returnsig_test.go`) rebuilds line 4 from line 3
    /// with `ReturnSigMessage` and verifies the signature under line 2.
    /// Regenerate with `SAKSI_WRITE_VECTORS=1 cargo test -p saksi-auditor
    /// --features demo return_signature_golden_vector`.
    #[test]
    fn return_signature_golden_vector() {
        let r = vector_return();
        let body = format!(
            "{}\n{}\n{}\n{}\n",
            hex::encode(vector_key().to_bytes()),
            hex::encode(pubkey(&vector_key())),
            serde_json::to_string(&r).unwrap(),
            hex::encode(r.message()),
        );
        if std::env::var_os("SAKSI_WRITE_VECTORS").is_some() {
            std::fs::write(vector_path(), &body).expect("write vector");
        }
        let on_disk = std::fs::read_to_string(vector_path()).expect("read er-sig-v1.hex");
        assert_eq!(on_disk.replace("\r\n", "\n"), body, "golden vector drifted");
        let lines: Vec<&str> = on_disk.lines().collect();
        let parsed: PrecinctReturn = serde_json::from_str(lines[2]).unwrap();
        parsed
            .verify(&parse_hex32(lines[1], "pubkey").unwrap())
            .expect("vector signature verifies");
    }
}
