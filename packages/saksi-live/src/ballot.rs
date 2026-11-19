//! One position's ballot record, built the way the generator's `build_record`
//! (saksi-auditor `fixtures.rs`) builds it: present the credential for the
//! position (per-position nullifier), encrypt one bit per candidate slot under
//! the joint key with a CDS 0-or-1 proof bound to the nullifier, then prove the
//! slots sum to exactly one.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use saksi_crypto::{
    elgamal::{encrypt, Plaintext},
    nizk::{
        cds::{binding_context, CDSProof},
        selection::{prove_selection, selection_context},
    },
};
use saksi_protocol::{
    Ballot, Ciphertext as WireCiphertext, DKGTranscript, ElectionParameters, WIRE_VERSION,
};

use crate::{
    codec::{self, LiveResult},
    election::{joint_public_key, position_contests, tracking_code, BINDING_CONTEXT},
    issuance::{credential, issuer_public_key, CredentialParts},
};

/// `ballot` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BallotRequest {
    /// Hex `ElectionParameters` (as recorded by `CreateElection`).
    pub params: String,
    /// Hex `DKGTranscript` (as recorded by `PublishDKGTranscript`).
    pub dkg: String,
    /// The voter's credential (secret).
    pub credential: CredentialParts,
    /// The position this record votes in.
    pub position_id: String,
    /// 0-based index of the chosen candidate within the position.
    pub choice: usize,
}

/// `ballot` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BallotResponse {
    /// Hex `Ballot`, the exact `SubmitBallot` argument.
    pub ballot: String,
    /// The election id.
    pub election_id: String,
    /// The position voted in.
    pub position_id: String,
    /// The contest ids of the record's slots, in order.
    pub contest_ids: Vec<String>,
    /// Hex nullifier (32 bytes) of this record.
    pub nullifier: String,
    /// `BC-XXXX-XXXX`, the first 8 hex digits of the nullifier. It names the
    /// voter's slot for this position (every ballot this voter builds for
    /// the position has it), not this particular ballot.
    pub tracking_code: String,
    /// [`ballot_fingerprint`] of this record: names this particular ballot.
    /// The phone shows it before the voter chooses cast or challenge.
    pub ballot_fingerprint: String,
}

/// `kind` of a [`BallotOpening`].
pub const OPENING_KIND: &str = "saksi-live-ballot-opening-v1";

/// What a Benaloh challenge needs to open a ballot built by
/// [`build_ballot_with_opening`]: the per-slot ElGamal randomness and the
/// choice. **Secret**: with it anyone can read the ballot's vote. The phone
/// keeps it in memory only, for the cast-or-challenge decision, and drops it
/// when the ballot is cast. Its strings are wiped when it is dropped.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct BallotOpening {
    /// [`OPENING_KIND`].
    pub kind: String,
    /// SHA-256 of the ballot's protobuf bytes (hex), so an opening is only
    /// ever applied to the ballot it was made with.
    pub ballot_digest: String,
    /// The contest ids of the ballot's slots, in order.
    pub contest_ids: Vec<String>,
    /// 0-based index of the chosen candidate within the position.
    pub choice: usize,
    /// The ElGamal randomness `r_k` of slot `k` (scalar hex).
    pub randomness: Vec<String>,
}

fn digest_bytes(ballot_bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(ballot_bytes).into()
}

/// SHA-256 of a ballot's protobuf bytes, hex.
pub fn ballot_digest(ballot_bytes: &[u8]) -> String {
    hex::encode(digest_bytes(ballot_bytes))
}

/// The per-ballot fingerprint people compare: `SHA-256(ballot bytes)`, the
/// same digest as [`ballot_digest`], shown as
/// [`crate::election::short_fingerprint`] (first 16 bytes, eight groups of
/// four upper-case hex digits). `ballot bytes` are the record's protobuf
/// encoding exactly as submitted, which is what the chaincode stores and
/// `GetBallot` returns (hex), so anyone holding the record can recompute it.
/// Two ballots for the same voter and position share a tracking code but,
/// with fresh randomness, never a fingerprint.
pub fn ballot_fingerprint(ballot_bytes: &[u8]) -> String {
    crate::election::short_fingerprint(&digest_bytes(ballot_bytes))
}

/// Builds one ballot record. Refuses a credential the election's issuer did
/// not sign, a transcript that is not the election's, an unknown position and
/// a choice outside the position's candidates.
pub fn build_ballot(
    req: &BallotRequest,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<BallotResponse> {
    build(req, rng, None)
}

/// [`build_ballot`], also returning the ballot's [`BallotOpening`] for a
/// Benaloh challenge. For the same random stream the ballot bytes are exactly
/// [`build_ballot`]'s: the randomness is copied out, not drawn differently.
///
/// A ballot that is challenged (opened) must never be submitted: the caller
/// discards it and builds a fresh one, with fresh randomness.
pub fn build_ballot_with_opening(
    req: &BallotRequest,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<(BallotResponse, BallotOpening)> {
    let mut randomness = Vec::new();
    let built = build(req, rng, Some(&mut randomness));
    let response = match built {
        Ok(r) => r,
        Err(e) => {
            randomness.zeroize();
            return Err(e);
        }
    };
    let bytes = codec::bytes(&response.ballot, "ballot")?;
    let opening = BallotOpening {
        kind: OPENING_KIND.into(),
        ballot_digest: ballot_digest(&bytes),
        contest_ids: response.contest_ids.clone(),
        choice: req.choice,
        randomness: randomness.iter().map(codec::scalar_hex).collect(),
    };
    randomness.zeroize();
    Ok((response, opening))
}

/// The builder. When `keep` is given, each slot's randomness is copied into
/// it before it is wiped; nothing else differs, so the random stream and the
/// ballot bytes are the same either way.
fn build(
    req: &BallotRequest,
    rng: &mut (impl RngCore + CryptoRng),
    mut keep: Option<&mut Vec<Scalar>>,
) -> LiveResult<BallotResponse> {
    let params: ElectionParameters = codec::message(&req.params, "params")?;
    let transcript: DKGTranscript = codec::message(&req.dkg, "dkg")?;
    if params.issuer_public_key.is_empty() {
        return Err("the election parameters carry no issuer key".into());
    }
    let issuer = issuer_public_key(&hex::encode(&params.issuer_public_key))?;
    let public_key = joint_public_key(&params, &transcript)?;
    let contests = position_contests(&params, &req.position_id)?;
    if req.choice >= contests.len() {
        return Err(format!(
            "choice {} is outside position {:?}'s {} candidates",
            req.choice,
            req.position_id,
            contests.len()
        ));
    }
    let credential = credential(&req.credential, &issuer)?;

    let election_id = params.election_id.as_bytes();
    let presentation = credential.present(
        &issuer,
        election_id,
        req.position_id.as_bytes(),
        BINDING_CONTEXT,
        rng,
    );
    let nullifier = presentation
        .nullifier
        .as_ref()
        .ok_or("presentation has no nullifier")?
        .value
        .clone();

    let choice_set = [Scalar::ZERO, Scalar::ONE];
    let mut ciphertexts = Vec::with_capacity(contests.len());
    let mut proofs = Vec::with_capacity(contests.len());
    let mut cts = Vec::with_capacity(contests.len());
    let mut r_sum = Scalar::ZERO;
    for (slot, contest_id) in contests.iter().enumerate() {
        let bit = usize::from(slot == req.choice);
        let mut r = Scalar::random(&mut *rng);
        let ct = encrypt(&public_key, Plaintext::from_small_integer(bit as u64), r);
        r_sum += r;
        if let Some(keep) = keep.as_deref_mut() {
            keep.push(r);
        }
        let context = binding_context(election_id, contest_id.as_bytes(), &nullifier);
        let proof = CDSProof::prove(&public_key, &ct, &choice_set, bit, &r, &context, rng);
        r.zeroize();
        let proof = match proof {
            Ok(p) => p,
            Err(e) => {
                r_sum.zeroize();
                return Err(format!("CDS prove for {contest_id}: {e}"));
            }
        };
        let (pad, data) = ct.to_compressed_bytes();
        ciphertexts.push(WireCiphertext {
            version: WIRE_VERSION,
            pad: pad.to_vec(),
            data: data.to_vec(),
        });
        proofs.push(proof.to_wire());
        cts.push(ct);
    }
    let selection = prove_selection(
        &public_key,
        &cts,
        &r_sum,
        &selection_context(election_id, req.position_id.as_bytes(), &nullifier),
        rng,
    );
    r_sum.zeroize();

    let ballot = Ballot {
        version: WIRE_VERSION,
        election_id: params.election_id.clone(),
        voter_credential_commitment: presentation.credential_commitment.clone(),
        ciphertexts,
        well_formedness_proofs: proofs,
        credential_presentation: Some(presentation),
        position_id: req.position_id.clone(),
        selection_proof: Some(selection.to_wire()),
    };
    let bytes = prost::Message::encode_to_vec(&ballot);
    Ok(BallotResponse {
        ballot: hex::encode(&bytes),
        ballot_fingerprint: ballot_fingerprint(&bytes),
        election_id: params.election_id,
        position_id: req.position_id.clone(),
        contest_ids: contests,
        tracking_code: tracking_code(&nullifier),
        nullifier: hex::encode(&nullifier),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{election, StreamRng};

    #[test]
    fn the_opening_variant_builds_the_same_bytes_for_the_same_stream() {
        let e = election("live-open");
        for (position, choice) in [("president", 0), ("president", 2), ("secretary", 1)] {
            let req = e.request(position, choice);
            let plain = build_ballot(&req, &mut StreamRng::new(7)).unwrap();
            let (with, opening) = build_ballot_with_opening(&req, &mut StreamRng::new(7)).unwrap();
            assert_eq!(plain.ballot, with.ballot, "{position}/{choice}");
            assert_eq!(plain.nullifier, with.nullifier);
            assert_eq!(plain.tracking_code, with.tracking_code);
            assert_eq!(plain.ballot_fingerprint, with.ballot_fingerprint);
            assert_eq!(opening.kind, OPENING_KIND);
            assert_eq!(opening.choice, choice);
            assert_eq!(opening.randomness.len(), 3);
            assert_eq!(opening.contest_ids, plain.contest_ids);
            assert_eq!(
                opening.ballot_digest,
                ballot_digest(&hex::decode(&plain.ballot).unwrap())
            );
            // The same stream twice gives the same ballot; another stream
            // does not.
            let other = build_ballot(&req, &mut StreamRng::new(8)).unwrap();
            assert_ne!(other.ballot, plain.ballot);
            // The nullifier, and so the tracking code, is per voter per
            // position; the ballot fingerprint is per ballot.
            assert_eq!(other.nullifier, plain.nullifier);
            assert_eq!(other.tracking_code, plain.tracking_code);
            assert_ne!(other.ballot_fingerprint, plain.ballot_fingerprint);
            // Anyone can recompute it from the record bytes alone.
            let bytes = hex::decode(&plain.ballot).unwrap();
            assert_eq!(plain.ballot_fingerprint, ballot_fingerprint(&bytes));
            assert_eq!(plain.ballot_fingerprint.len(), 39);
            assert_eq!(
                plain.ballot_fingerprint.replace('-', ""),
                opening.ballot_digest[..32].to_uppercase()
            );
        }
    }

    #[test]
    fn the_opening_variant_refuses_what_the_builder_refuses() {
        let e = election("live-open-bad");
        let mut req = e.request("president", 3);
        assert!(build_ballot_with_opening(&req, &mut StreamRng::new(1))
            .err()
            .unwrap()
            .contains("outside"));
        req.choice = 0;
        req.position_id = "treasurer".into();
        assert!(build_ballot_with_opening(&req, &mut StreamRng::new(1)).is_err());
    }
}
