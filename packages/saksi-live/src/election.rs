//! Election-level helpers shared by every party: the parameters a live
//! election is created with, the joint key read from a published DKG
//! transcript, the contests a position covers, and the tracking code.

use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};
use serde::{Deserialize, Serialize};

use saksi_crypto::elgamal::PublicKey;
use saksi_protocol::{DKGTranscript, ElectionParameters, WIRE_VERSION};

use crate::codec::{self, LiveResult};

/// The binding context every live NIZK is made under. It is the generator's
/// `saksi-auditor-v1`, so the auditor, the chaincode and the existing board
/// read a live election exactly as they read a generated one.
pub const BINDING_CONTEXT: &[u8] = b"saksi-auditor-v1";

/// Longest id accepted for an election, a position or a candidate.
pub const MAX_ID_LEN: usize = 64;

/// Longest contest id `<position>/<candidate>`. A partial decryption's
/// Chaum-Pedersen context length-prefixes the contest id with 8 big-endian
/// bytes, and `partial_decrypt_v2` takes that context as a UTF-8 string: the
/// prefix's low byte must be ASCII (`< 0x80`), so the id is at most 127 bytes.
/// Refused at creation, so an election that could not be decrypted is never
/// created.
pub const MAX_CONTEST_ID_LEN: usize = 127;

/// One position and its candidates, in ballot order.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Position {
    /// Position id, e.g. `president`. Becomes the contest-id prefix.
    pub id: String,
    /// Candidate ids, e.g. `["alice", "bob", "carol"]`.
    pub candidates: Vec<String>,
}

/// `election-params` input.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamsRequest {
    /// The election id every artifact is bound to.
    pub election_id: String,
    /// Positions in ballot order.
    pub positions: Vec<Position>,
    /// Number of trustees `n`; their ids are `"1"..="n"`.
    pub trustees: usize,
    /// Decryption threshold `t`, `1 <= t <= n`.
    pub threshold: usize,
    /// Hex of the issuer public key (`issuer-keygen`'s `public_key`).
    pub issuer_public_key: String,
}

/// `election-params` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParamsResponse {
    /// Hex `ElectionParameters`, the exact `CreateElection` argument.
    pub params: String,
    /// The election id.
    pub election_id: String,
    /// Contest ids in order: `<position>/<candidate>`.
    pub contest_ids: Vec<String>,
    /// Trustee ids `"1"..="n"`.
    pub trustee_ids: Vec<String>,
    /// The threshold.
    pub threshold: u32,
}

fn check_id(id: &str, what: &str) -> LiveResult<()> {
    if id.is_empty() || id.len() > MAX_ID_LEN {
        return Err(format!("{what} must be 1..={MAX_ID_LEN} bytes"));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(format!(
            "{what} {id:?} may only use ASCII letters, digits, '-', '_' and '.'"
        ));
    }
    Ok(())
}

/// Builds the `ElectionParameters` of a live election.
///
/// Contest ids are `<position>/<candidate>`, the prefix rule the chaincode and
/// the auditor use to route a ballot record to its position. Trustee ids are
/// `"1".."n"` in order, because the DKG evaluates trustee `k`'s share at
/// `x = k` and every verifier maps a trustee id to its position in this list.
pub fn election_params(req: &ParamsRequest) -> LiveResult<ParamsResponse> {
    check_id(&req.election_id, "election_id")?;
    if req.positions.is_empty() {
        return Err("an election needs at least one position".into());
    }
    if req.trustees == 0 || req.threshold == 0 || req.threshold > req.trustees {
        return Err(format!(
            "threshold {} of {} trustees is not 1 <= t <= n",
            req.threshold, req.trustees
        ));
    }
    let issuer = codec::nonzero_point(&req.issuer_public_key, "issuer_public_key")?;
    let mut contest_ids = Vec::new();
    let mut seen_positions = std::collections::HashSet::new();
    for position in &req.positions {
        check_id(&position.id, "position id")?;
        if !seen_positions.insert(position.id.as_str()) {
            return Err(format!("position {:?} is listed twice", position.id));
        }
        if position.candidates.is_empty() {
            return Err(format!("position {:?} has no candidates", position.id));
        }
        let mut seen = std::collections::HashSet::new();
        for candidate in &position.candidates {
            check_id(candidate, "candidate id")?;
            if !seen.insert(candidate.as_str()) {
                return Err(format!(
                    "candidate {candidate:?} is listed twice in position {:?}",
                    position.id
                ));
            }
            let contest_id = format!("{}/{candidate}", position.id);
            if contest_id.len() > MAX_CONTEST_ID_LEN {
                return Err(format!(
                    "contest id {contest_id:?} is {} bytes; position and candidate ids together must be at most {MAX_CONTEST_ID_LEN} bytes including the '/'",
                    contest_id.len()
                ));
            }
            contest_ids.push(contest_id);
        }
    }
    let trustee_ids: Vec<String> = (1..=req.trustees).map(|i| i.to_string()).collect();
    let params = ElectionParameters {
        version: WIRE_VERSION,
        election_id: req.election_id.clone(),
        contest_ids: contest_ids.clone(),
        trustee_ids: trustee_ids.clone(),
        threshold: req.threshold as u32,
        issuer_public_key: issuer.compress().to_bytes().to_vec(),
    };
    Ok(ParamsResponse {
        params: codec::message_hex(&params),
        election_id: req.election_id.clone(),
        contest_ids,
        trustee_ids,
        threshold: req.threshold as u32,
    })
}

/// Checks that `transcript` belongs to `params` (id, threshold, one dealer per
/// trustee, `t` commitments each) and returns the joint ElGamal key
/// `Y = Σ_d A_{d,0}`, the sum the chaincode's `deriveElectionPublicKey` takes.
pub fn joint_public_key(
    params: &ElectionParameters,
    transcript: &DKGTranscript,
) -> LiveResult<PublicKey> {
    if transcript.version != WIRE_VERSION {
        return Err(format!("DKG transcript version {}", transcript.version));
    }
    if transcript.election_id != params.election_id {
        return Err(format!(
            "DKG transcript is for election {:?}, not {:?}",
            transcript.election_id, params.election_id
        ));
    }
    if transcript.threshold != params.threshold {
        return Err("DKG transcript threshold differs from the election's".into());
    }
    if transcript.trustee_commitments.len() != params.trustee_ids.len() {
        return Err("DKG transcript does not carry one dealer per trustee".into());
    }
    let mut joint = RistrettoPoint::identity();
    for commitment in &transcript.trustee_commitments {
        if commitment.coefficient_commitments.len() != params.threshold as usize {
            return Err(format!(
                "dealer {} has {} commitments, want {}",
                commitment.trustee_id,
                commitment.coefficient_commitments.len(),
                params.threshold
            ));
        }
        let a0 = <[u8; 32]>::try_from(commitment.coefficient_commitments[0].as_slice()).map_err(
            |_| {
                format!(
                    "dealer {} constant term is not 32 bytes",
                    commitment.trustee_id
                )
            },
        )?;
        joint += saksi_crypto::group::point_from_compressed(a0).map_err(|_| {
            format!(
                "dealer {} constant term is not a point",
                commitment.trustee_id
            )
        })?;
    }
    if joint == RistrettoPoint::identity() {
        return Err("the DKG transcript's joint public key is the identity: every vote would be in the clear".into());
    }
    Ok(PublicKey::from_point(joint))
}

/// The contest ids `position_id` covers, in order: the contests named
/// `<position_id>/...`, the prefix rule of the chaincode's
/// `contestIndicesForPosition`. An empty position (the legacy whole-ballot
/// record) is refused: a live election's contests are always per position.
pub fn position_contests(
    params: &ElectionParameters,
    position_id: &str,
) -> LiveResult<Vec<String>> {
    if position_id.is_empty() {
        return Err("position_id is empty".into());
    }
    let prefix = format!("{position_id}/");
    let contests: Vec<String> = params
        .contest_ids
        .iter()
        .filter(|c| c.starts_with(&prefix))
        .cloned()
        .collect();
    if contests.is_empty() {
        return Err(format!(
            "position {position_id:?} has no contests in this election"
        ));
    }
    Ok(contests)
}

/// The voter-facing tracking code of a ballot record: `BC-` and the first 8
/// hex digits of its nullifier, upper case, as `BC-XXXX-XXXX`. The board's
/// `formatTrackingCode` (saksi-campaign `board.go`) computes the same string,
/// including the empty string for a nullifier shorter than 4 bytes.
pub fn tracking_code(nullifier: &[u8]) -> String {
    if nullifier.len() < 4 {
        return String::new();
    }
    let h = hex::encode_upper(&nullifier[..4]);
    format!("BC-{}-{}", &h[..4], &h[4..8])
}

/// Domain of [`ballot_set_digest`].
pub const BALLOT_SET_DOMAIN: &[u8] = b"saksi.live.ballot-set.v1";

/// An order-independent digest of a set of ballot records, so a trustee page,
/// the board and the other trustees can confirm they aggregated the same
/// ballots: `SHA-256(BALLOT_SET_DOMAIN || u64be(len election_id) ||
/// election_id || u64be(n) || sorted(SHA-256(ballot_bytes_i))...)`, where
/// `ballot_bytes_i` is each record's protobuf encoding.
pub fn ballot_set_digest(election_id: &str, ballots: &[Vec<u8>]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut leaves: Vec<[u8; 32]> = ballots.iter().map(|b| Sha256::digest(b).into()).collect();
    leaves.sort_unstable();
    let mut h = Sha256::new();
    h.update(BALLOT_SET_DOMAIN);
    h.update((election_id.len() as u64).to_be_bytes());
    h.update(election_id.as_bytes());
    h.update((ballots.len() as u64).to_be_bytes());
    for leaf in &leaves {
        h.update(leaf);
    }
    h.finalize().into()
}

/// A digest's short form, `XXXX-XXXX-XXXX-XXXX` (first 8 bytes, upper hex).
pub fn short_fingerprint(digest: &[u8; 32]) -> String {
    let d = hex::encode_upper(&digest[..8]);
    format!("{}-{}-{}-{}", &d[0..4], &d[4..8], &d[8..12], &d[12..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ParamsRequest {
        let pk = saksi_crypto::group::basepoint() * curve25519_dalek::scalar::Scalar::from(5u64);
        ParamsRequest {
            election_id: "live-1".into(),
            positions: vec![
                Position {
                    id: "president".into(),
                    candidates: vec!["a".into(), "b".into()],
                },
                Position {
                    id: "vp".into(),
                    candidates: vec!["c".into()],
                },
            ],
            trustees: 5,
            threshold: 3,
            issuer_public_key: codec::point_hex(&pk),
        }
    }

    #[test]
    fn params_use_position_prefixed_contests_and_numbered_trustees() {
        let out = election_params(&request()).unwrap();
        assert_eq!(out.contest_ids, ["president/a", "president/b", "vp/c"]);
        assert_eq!(out.trustee_ids, ["1", "2", "3", "4", "5"]);
        let params: ElectionParameters = codec::message(&out.params, "params").unwrap();
        assert_eq!(position_contests(&params, "president").unwrap().len(), 2);
        assert!(position_contests(&params, "pres").is_err());
    }

    #[test]
    fn params_refuse_bad_shapes() {
        let mut r = request();
        r.positions[0].id = "a/b".into();
        assert!(election_params(&r).is_err());
        let mut r = request();
        r.threshold = 6;
        assert!(election_params(&r).is_err());
        let mut r = request();
        r.positions[1].candidates.clear();
        assert!(election_params(&r).is_err());
    }

    #[test]
    fn tracking_code_matches_the_board_format() {
        let n = hex::decode("7f3a92c1deadbeef").unwrap();
        assert_eq!(tracking_code(&n), "BC-7F3A-92C1");
        assert_eq!(tracking_code(&n[..3]), "");
    }

    #[test]
    fn contest_ids_stop_at_127_bytes() {
        let mut r = request();
        r.positions = vec![Position {
            id: "p".repeat(63),
            candidates: vec!["c".repeat(63)],
        }];
        let out = election_params(&r).unwrap();
        assert_eq!(out.contest_ids[0].len(), 127);
        r.positions[0].id = "p".repeat(64);
        let err = election_params(&r).unwrap_err();
        assert!(err.contains("at most 127"), "{err}");
    }

    #[test]
    fn an_identity_joint_key_is_refused() {
        use saksi_protocol::TrusteeCommitment;
        let params: ElectionParameters =
            codec::message(&election_params(&request()).unwrap().params, "p").unwrap();
        let g = saksi_crypto::group::basepoint();
        let a = curve25519_dalek::scalar::Scalar::from(11u64);
        let commit = |p: RistrettoPoint| TrusteeCommitment {
            trustee_id: String::new(),
            coefficient_commitments: vec![p.compress().to_bytes().to_vec(); 3],
        };
        let mut transcript = DKGTranscript {
            version: WIRE_VERSION,
            election_id: params.election_id.clone(),
            threshold: 3,
            trustee_commitments: (0..5).map(|_| commit(a * g)).collect(),
            complaints: vec![],
        };
        assert!(joint_public_key(&params, &transcript).is_ok());
        // Dealer 5 publishes the negation of the others' constant terms.
        transcript.trustee_commitments[4] =
            commit(-(a * g) * curve25519_dalek::scalar::Scalar::from(4u64));
        let err = joint_public_key(&params, &transcript).err().unwrap();
        assert!(err.contains("identity"), "{err}");
    }

    #[test]
    fn ballot_set_digest_ignores_order_and_binds_contents() {
        let a = vec![1u8, 2];
        let b = vec![3u8];
        let d = ballot_set_digest("e", &[a.clone(), b.clone()]);
        assert_eq!(d, ballot_set_digest("e", &[b.clone(), a.clone()]));
        assert_ne!(d, ballot_set_digest("e", std::slice::from_ref(&a)));
        assert_ne!(d, ballot_set_digest("f", &[a, b]));
    }
}
