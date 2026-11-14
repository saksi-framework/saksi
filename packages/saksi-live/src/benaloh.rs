//! The voter's Benaloh challenge ("cast or challenge").
//!
//! After the phone builds a ballot with
//! [`crate::ballot::build_ballot_with_opening`], the voter either casts it
//! (the phone submits it and drops the opening) or challenges it: the phone
//! [`open`]s it, revealing every slot's ElGamal randomness and plaintext, and
//! [`check`] re-encrypts each slot under the election's joint key with the
//! revealed randomness. If every slot reproduces the ballot's ciphertext, the
//! ballot encodes exactly the plaintexts revealed, so the voter can see that
//! the phone encrypted the candidate they chose.
//!
//! A challenged ballot must never be submitted: its vote is now public to
//! whoever saw the opening. The caller discards it and builds a fresh ballot
//! with fresh randomness. The fresh ballot carries the **same nullifier** (the
//! nullifier is a function of the credential, the election and the position,
//! one per voter per position), so it gets the same tracking code. That is
//! fine because the challenged ballot never reaches the chain: the chain sees
//! the nullifier once, on the ballot that is cast. It does mean an opening
//! links the challenged choice to the voter's tracking code, which is why the
//! opened values stay on the phone.
//!
//! [`check`] is only as independent as the code that runs it. The opened
//! values are plain JSON, so any other implementation (the
//! `saksi-demo live benaloh-check` op, or a second device) can check them too.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use saksi_crypto::elgamal::{encrypt, Plaintext};
use saksi_protocol::{Ballot, DKGTranscript, ElectionParameters};

use crate::{
    ballot::{ballot_digest, BallotOpening, OPENING_KIND},
    codec::{self, LiveResult},
    election::{joint_public_key, position_contests, tracking_code},
};

/// One opened slot.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct OpenedSlot {
    /// The slot's contest id, `<position>/<candidate>`.
    pub contest_id: String,
    /// The claimed plaintext: 1 for the chosen candidate, 0 otherwise.
    pub plaintext: u64,
    /// The slot's ElGamal randomness (scalar hex).
    pub randomness: String,
}

/// A challenged ballot's opened values: the [`open`] output and the `opened`
/// input of [`check`]. Public once shown, but it reveals the challenged
/// ballot's vote; its strings are wiped when it is dropped.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Opened {
    /// The ballot's election id.
    pub election_id: String,
    /// The ballot's position id.
    pub position_id: String,
    /// The ballot's nullifier (hex).
    pub nullifier: String,
    /// The tracking code the ballot would have had.
    pub tracking_code: String,
    /// Every slot, in the ballot's order.
    pub slots: Vec<OpenedSlot>,
}

/// `benaloh_open` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRequest {
    /// Hex `Ballot`, as built.
    pub ballot: String,
    /// The opening [`crate::ballot::build_ballot_with_opening`] returned
    /// with it.
    pub opening: BallotOpening,
}

/// `benaloh_check` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    /// Hex `ElectionParameters`.
    pub params: String,
    /// Hex `DKGTranscript`.
    pub dkg: String,
    /// Hex `Ballot`, the challenged one.
    pub ballot: String,
    /// The [`open`] output for it.
    pub opened: Opened,
}

/// One slot's verdict.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlotCheck {
    /// The slot's contest id.
    pub contest_id: String,
    /// The claimed plaintext.
    pub plaintext: u64,
    /// Whether `Enc(Y, plaintext; randomness)` equals the ballot's ciphertext.
    pub reproduces: bool,
}

/// `benaloh_check` output.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResponse {
    /// True iff every slot reproduces its ciphertext and exactly one slot
    /// holds 1 and the rest 0: the ballot encodes `encoded_candidate`.
    pub valid: bool,
    /// The ballot's position id.
    pub position_id: String,
    /// The ballot's tracking code.
    pub tracking_code: String,
    /// Every slot's verdict, in the ballot's order.
    pub slots: Vec<SlotCheck>,
    /// 0-based index of the candidate the ballot encodes, when `valid`.
    pub encoded_choice: Option<usize>,
    /// The candidate id the ballot encodes (the contest id after
    /// `<position>/`), when `valid`.
    pub encoded_candidate: Option<String>,
}

fn decode_ballot(hex_ballot: &str) -> LiveResult<(Ballot, Vec<u8>)> {
    let bytes = codec::bytes(hex_ballot, "ballot")?;
    let ballot: Ballot = prost::Message::decode(bytes.as_slice())
        .map_err(|e| format!("ballot does not decode: {e}"))?;
    Ok((ballot, bytes))
}

fn nullifier(ballot: &Ballot) -> LiveResult<Vec<u8>> {
    Ok(ballot
        .credential_presentation
        .as_ref()
        .and_then(|p| p.nullifier.as_ref())
        .ok_or("the ballot has no nullifier")?
        .value
        .clone())
}

/// Opens a challenged ballot: refuses an opening made for another ballot, and
/// returns every slot's randomness and plaintext.
pub fn open(req: &OpenRequest) -> LiveResult<Opened> {
    let o = &req.opening;
    if o.kind != OPENING_KIND {
        return Err(format!("opening kind is not {OPENING_KIND}"));
    }
    let (ballot, bytes) = decode_ballot(&req.ballot)?;
    if ballot_digest(&bytes) != o.ballot_digest {
        return Err("this opening is not for this ballot".into());
    }
    let n = ballot.ciphertexts.len();
    if o.randomness.len() != n || o.contest_ids.len() != n {
        return Err(format!(
            "the opening has {} slots, the ballot {n}",
            o.randomness.len()
        ));
    }
    if o.choice >= n {
        return Err(format!(
            "the opening's choice {} is outside {n} slots",
            o.choice
        ));
    }
    let nullifier = nullifier(&ballot)?;
    Ok(Opened {
        election_id: ballot.election_id.clone(),
        position_id: ballot.position_id.clone(),
        tracking_code: tracking_code(&nullifier),
        nullifier: hex::encode(&nullifier),
        slots: o
            .contest_ids
            .iter()
            .zip(&o.randomness)
            .enumerate()
            .map(|(k, (contest_id, r))| OpenedSlot {
                contest_id: contest_id.clone(),
                plaintext: u64::from(k == o.choice),
                randomness: r.clone(),
            })
            .collect(),
    })
}

/// Checks a challenged ballot's opened values against the election: each
/// slot is re-encrypted under the joint key the transcript gives, with the
/// revealed randomness, and compared with the ballot's ciphertext.
///
/// Refuses (an error, not a verdict) a ballot or opening that is not for this
/// election, this position's contests or this ballot's nullifier; a
/// randomness that is not a canonical scalar is a slot that does not
/// reproduce.
pub fn check(req: &CheckRequest) -> LiveResult<CheckResponse> {
    let params: ElectionParameters = codec::message(&req.params, "params")?;
    let transcript: DKGTranscript = codec::message(&req.dkg, "dkg")?;
    let public_key = joint_public_key(&params, &transcript)?;
    let (ballot, _) = decode_ballot(&req.ballot)?;
    let o = &req.opened;
    if ballot.election_id != params.election_id || o.election_id != params.election_id {
        return Err("the ballot or the opening is not for this election".into());
    }
    if o.position_id != ballot.position_id {
        return Err("the opening is for another position than the ballot".into());
    }
    let contests = position_contests(&params, &ballot.position_id)?;
    let nullifier = nullifier(&ballot)?;
    if o.nullifier != hex::encode(&nullifier) {
        return Err("the opening is for another ballot's nullifier".into());
    }
    if ballot.ciphertexts.len() != contests.len() || o.slots.len() != contests.len() {
        return Err(format!(
            "position {:?} has {} contests; the ballot has {} slots and the opening {}",
            ballot.position_id,
            contests.len(),
            ballot.ciphertexts.len(),
            o.slots.len()
        ));
    }
    let mut slots = Vec::with_capacity(contests.len());
    for ((contest_id, slot), ct) in contests.iter().zip(&o.slots).zip(&ballot.ciphertexts) {
        if &slot.contest_id != contest_id {
            return Err(format!(
                "opened slot {:?} is not the election's contest {contest_id:?}",
                slot.contest_id
            ));
        }
        let reproduces = match codec::scalar(&slot.randomness, "randomness") {
            Ok(mut r) => {
                let again = encrypt(
                    &public_key,
                    Plaintext::from_small_integer(slot.plaintext),
                    r,
                );
                r.zeroize();
                let (pad, data) = again.to_compressed_bytes();
                pad.as_slice() == ct.pad.as_slice() && data.as_slice() == ct.data.as_slice()
            }
            Err(_) => false,
        };
        slots.push(SlotCheck {
            contest_id: contest_id.clone(),
            plaintext: slot.plaintext,
            reproduces,
        });
    }
    let ones: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.plaintext == 1)
        .map(|(k, _)| k)
        .collect();
    let well_formed = slots.iter().all(|s| s.reproduces && s.plaintext <= 1) && ones.len() == 1;
    let encoded_choice = well_formed.then(|| ones[0]);
    let prefix = format!("{}/", ballot.position_id);
    let encoded_candidate = encoded_choice.map(|k| {
        contests[k]
            .strip_prefix(&prefix)
            .unwrap_or(&contests[k])
            .to_string()
    });
    Ok(CheckResponse {
        valid: well_formed,
        position_id: ballot.position_id.clone(),
        tracking_code: tracking_code(&nullifier),
        slots,
        encoded_choice,
        encoded_candidate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ballot::build_ballot_with_opening;
    use crate::test_support::election;
    use rand_core::OsRng;

    fn opened_ballot(choice: usize) -> (crate::test_support::TestElection, String, Opened) {
        let e = election("live-benaloh");
        let (built, opening) =
            build_ballot_with_opening(&e.request("president", choice), &mut OsRng).unwrap();
        let opened = open(&OpenRequest {
            ballot: built.ballot.clone(),
            opening,
        })
        .unwrap();
        assert_eq!(opened.tracking_code, built.tracking_code);
        assert_eq!(opened.nullifier, built.nullifier);
        (e, built.ballot, opened)
    }

    fn run(e: &crate::test_support::TestElection, ballot: &str, opened: Opened) -> CheckResponse {
        check(&CheckRequest {
            params: e.params.clone(),
            dkg: e.dkg.clone(),
            ballot: ballot.into(),
            opened,
        })
        .unwrap()
    }

    #[test]
    fn an_honest_opening_checks_and_names_the_candidate() {
        for choice in 0..3 {
            let (e, ballot, opened) = opened_ballot(choice);
            let v = run(&e, &ballot, opened);
            assert!(v.valid, "{v:?}");
            assert!(v.slots.iter().all(|s| s.reproduces));
            assert_eq!(v.encoded_choice, Some(choice));
            assert_eq!(
                v.encoded_candidate.as_deref(),
                Some(["alice", "bob", "carol"][choice])
            );
            assert_eq!(v.position_id, "president");
        }
    }

    #[test]
    fn a_changed_randomness_fails() {
        let (e, ballot, mut opened) = opened_ballot(1);
        let r = codec::scalar(&opened.slots[0].randomness, "r").unwrap();
        opened.slots[0].randomness =
            codec::scalar_hex(&(r + curve25519_dalek::scalar::Scalar::ONE));
        let v = run(&e, &ballot, opened);
        assert!(!v.valid);
        assert!(!v.slots[0].reproduces);
        assert!(v.slots[1].reproduces && v.slots[2].reproduces);
        assert_eq!(v.encoded_choice, None);
        assert_eq!(v.encoded_candidate, None);
    }

    #[test]
    fn a_changed_claimed_candidate_fails() {
        // The ballot encodes bob; the opening claims carol.
        let (e, ballot, mut opened) = opened_ballot(1);
        opened.slots[1].plaintext = 0;
        opened.slots[2].plaintext = 1;
        let v = run(&e, &ballot, opened);
        assert!(!v.valid);
        assert!(v.slots[0].reproduces);
        assert!(!v.slots[1].reproduces && !v.slots[2].reproduces);
        assert_eq!(v.encoded_candidate, None);
    }

    #[test]
    fn a_non_scalar_randomness_is_a_slot_that_does_not_reproduce() {
        let (e, ballot, mut opened) = opened_ballot(0);
        opened.slots[2].randomness = "ff".repeat(32);
        let v = run(&e, &ballot, opened);
        assert!(!v.valid);
        assert!(!v.slots[2].reproduces);
    }

    #[test]
    fn an_opening_for_another_ballot_is_refused() {
        let e = election("live-benaloh-other");
        let (a, _) = build_ballot_with_opening(&e.request("president", 0), &mut OsRng).unwrap();
        let (_, opening_b) =
            build_ballot_with_opening(&e.request("president", 0), &mut OsRng).unwrap();
        let err = open(&OpenRequest {
            ballot: a.ballot.clone(),
            opening: opening_b,
        })
        .err()
        .unwrap();
        assert!(err.contains("not for this ballot"), "{err}");

        // An opening checked against another position's ballot is refused.
        let (_, _, opened) = opened_ballot(0);
        let (sec, _) = build_ballot_with_opening(&e.request("secretary", 0), &mut OsRng).unwrap();
        assert!(check(&CheckRequest {
            params: e.params.clone(),
            dkg: e.dkg.clone(),
            ballot: sec.ballot,
            opened,
        })
        .is_err());
    }

    #[test]
    fn the_challenge_reveals_no_secret_in_its_errors() {
        let e = election("live-benaloh-err");
        let (a, opening) =
            build_ballot_with_opening(&e.request("president", 0), &mut OsRng).unwrap();
        let secret = opening.randomness[0].clone();
        let mut bad = opening.clone();
        bad.kind = "x".into();
        let err = open(&OpenRequest {
            ballot: a.ballot.clone(),
            opening: bad,
        })
        .err()
        .unwrap();
        assert!(!err.contains(&secret));
    }
}
