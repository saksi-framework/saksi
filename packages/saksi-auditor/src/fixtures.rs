//! Synthetic happy-path election builder used by the auditor's tamper tests.
//!
//! Builds a 5-trustee / threshold-3, 2-contest, 6-voter election end-to-end:
//!
//! - generate an issuer keypair and issue 6 credentials via the full
//!   Pointcheval-Stern blind-Schnorr issuance ceremony,
//! - run the in-memory Pedersen DKG to produce trustee shares + a joint
//!   public key,
//! - encrypt each voter's choice for each of the two contests under the
//!   joint key, produce a CDS OR-proof per ciphertext, and a credential
//!   presentation per ballot,
//! - have every trustee partial-decrypt every contest's aggregate ciphertext
//!   with a Chaum-Pedersen proof,
//! - publish a [`TallyResult`] whose `totals` equal the actual sum-of-yes
//!   per contest.
//!
//! The whole bundle is returned as an [`ElectionFixture`] whose owned wire
//! values can be borrowed into an [`crate::ElectionArtifacts`]. Tests mutate
//! one field of this struct, call [`crate::audit`], and assert.

#![cfg(test)]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand_core::OsRng;

use saksi_credentials::{
    issuer_pre_sign, issuer_sign, voter_begin_issuance, voter_blind_challenge,
    voter_finalize_issuance, Credential, IssuerPublicKey, IssuerSecretKey,
};
use saksi_crypto::{
    dkg::{run_in_memory, Dealer, DkgConfig, TrusteeShare},
    elgamal::{self, encrypt, Plaintext, PublicKey},
    group::{basepoint, compress_point},
    nizk::{cds::CDSProof, chaum_pedersen::ChaumPedersenProof},
};
use saksi_protocol::{
    Ballot, Ciphertext as WireCiphertext, DKGTranscript, ElectionParameters, PartialDecryption,
    TallyResult, WIRE_VERSION,
};

use crate::{ballot::cds_context_for_test, decryption::cp_context_for_test, ElectionArtifacts};

/// Auditor-side binding context used by the fixture and by tests that drive
/// the auditor directly.
pub(crate) const BINDING_CONTEXT: &[u8] = b"saksi-auditor-v1";

/// Fully realized election fixture.
pub(crate) struct ElectionFixture {
    pub(crate) parameters: ElectionParameters,
    pub(crate) dkg_transcript: DKGTranscript,
    pub(crate) ballots: Vec<Ballot>,
    pub(crate) partial_decryptions: Vec<PartialDecryption>,
    pub(crate) tally: TallyResult,
    pub(crate) issuer_public_key: IssuerPublicKey,
}

impl ElectionFixture {
    /// Borrow this fixture as an [`ElectionArtifacts`] for the auditor.
    pub(crate) fn artifacts(&self) -> ElectionArtifacts<'_> {
        ElectionArtifacts {
            parameters: &self.parameters,
            dkg_transcript: &self.dkg_transcript,
            ballots: &self.ballots,
            partial_decryptions: &self.partial_decryptions,
            tally: &self.tally,
            binding_context: BINDING_CONTEXT,
            issuer_public_key: &self.issuer_public_key,
        }
    }
}

/// Build the standard happy-path fixture used by every test.
///
/// Layout:
/// - 5 trustees with ids `"1".."5"`, threshold 3.
/// - 2 contests with ids `"contest-1"`, `"contest-2"`.
/// - 6 ballots. Voter `v` (0..6) encrypts choice `voter_choice(v, c)` for
///   contest `c`.
pub(crate) fn happy_path_fixture() -> ElectionFixture {
    let mut rng = OsRng;

    // -- election parameters ----------------------------------------------

    let trustee_ids: Vec<String> = (1..=5).map(|i: u32| i.to_string()).collect();
    let contest_ids: Vec<String> = vec!["contest-1".into(), "contest-2".into()];
    let threshold: u32 = 3;
    let parameters = ElectionParameters {
        version: WIRE_VERSION,
        election_id: "election-2026".into(),
        contest_ids: contest_ids.clone(),
        trustee_ids: trustee_ids.clone(),
        threshold,
    };

    // -- DKG --------------------------------------------------------------

    let config = DkgConfig::default_3_of_5();
    // Deterministic-ish dealers: same shape used in saksi-crypto's tests.
    let dealers: Vec<Dealer> = (1..=config.trustees)
        .map(|dealer_id| {
            Dealer::new(
                dealer_id,
                (0..config.threshold)
                    .map(|coefficient| Scalar::from((dealer_id * 13 + coefficient + 1) as u64))
                    .collect(),
            )
        })
        .collect();
    let dkg_output = run_in_memory(config, &dealers).expect("DKG completes");
    let dkg_transcript = dkg_output.to_protocol_transcript(parameters.election_id.clone());
    let election_public_key = dkg_output.public_key;

    // -- issuer + 6 credentials ------------------------------------------

    let issuer_sk = IssuerSecretKey::generate(&mut rng);
    let issuer_pk = issuer_sk.public_key();

    let mut credentials: Vec<Credential> = Vec::with_capacity(6);
    for _ in 0..6 {
        let (request, blind_state) = voter_begin_issuance(&mut rng);
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, &mut rng);
        let (blinded, finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, &mut rng);
        let response = issuer_sign(&issuer_sk, session, &blinded);
        let credential = voter_finalize_issuance(finalize_state, &response, &issuer_pk)
            .expect("issuance happy path");
        credentials.push(credential);
    }

    // -- ballots ----------------------------------------------------------

    let mut ballots: Vec<Ballot> = Vec::with_capacity(6);
    // Track per-contest plaintext tallies so we can publish a faithful
    // `TallyResult` below.
    let mut plaintext_tallies = vec![0u64; contest_ids.len()];

    for (voter_idx, credential) in credentials.iter().enumerate() {
        let serial = voter_idx as u64;
        let mut ciphertexts: Vec<WireCiphertext> = Vec::with_capacity(contest_ids.len());
        let mut proofs = Vec::with_capacity(contest_ids.len());

        for (contest_idx, contest_id) in contest_ids.iter().enumerate() {
            let choice = voter_choice(voter_idx, contest_idx);
            plaintext_tallies[contest_idx] += choice as u64;

            // Encrypt under the joint election public key.
            let r = Scalar::random(&mut rng);
            let plaintext = Plaintext::from_small_integer(choice as u64);
            let ct = encrypt(&election_public_key, plaintext, r);
            let (pad_bytes, data_bytes) = ct.to_compressed_bytes();
            ciphertexts.push(WireCiphertext {
                version: WIRE_VERSION,
                pad: pad_bytes.to_vec(),
                data: data_bytes.to_vec(),
            });

            // CDS OR-proof against {0, 1}.
            let choice_set = [Scalar::ZERO, Scalar::ONE];
            let context = cds_context_for_test(BINDING_CONTEXT, contest_id.as_bytes(), serial);
            let cds = CDSProof::prove(
                &election_public_key,
                &ct,
                &choice_set,
                choice as usize,
                &r,
                &context,
                &mut rng,
            )
            .expect("CDS prove ok");
            proofs.push(cds.to_wire());
        }

        let presentation = credential.present(
            &issuer_pk,
            parameters.election_id.as_bytes(),
            BINDING_CONTEXT,
            &mut rng,
        );

        ballots.push(Ballot {
            version: WIRE_VERSION,
            election_id: parameters.election_id.clone(),
            voter_credential_commitment: presentation.credential_commitment.clone(),
            ciphertexts,
            well_formedness_proofs: proofs,
            credential_presentation: Some(presentation),
        });
    }

    // -- aggregate per-contest ciphertexts -------------------------------

    let contest_count = contest_ids.len();
    let trustee_count = trustee_ids.len();
    let mut aggregate_pads = vec![RistrettoPoint::identity(); contest_count];
    let mut aggregate_data = vec![RistrettoPoint::identity(); contest_count];
    for ballot in &ballots {
        for (c, ct) in ballot.ciphertexts.iter().enumerate() {
            let pad: [u8; 32] = ct.pad.as_slice().try_into().unwrap();
            let data: [u8; 32] = ct.data.as_slice().try_into().unwrap();
            aggregate_pads[c] += saksi_crypto::group::point_from_compressed(pad).unwrap();
            aggregate_data[c] += saksi_crypto::group::point_from_compressed(data).unwrap();
        }
    }

    // -- partial decryptions: one PartialDecryption per (contest, trustee) -

    let mut partial_decryptions: Vec<PartialDecryption> =
        Vec::with_capacity(contest_count * trustee_count);
    for (c, contest_id) in contest_ids.iter().enumerate() {
        let aggregate_pad = aggregate_pads[c];
        for (t, trustee_id_str) in trustee_ids.iter().enumerate() {
            let trustee_share: &TrusteeShare = dkg_output
                .trustee_shares
                .iter()
                .find(|s| s.trustee_id == t + 1)
                .expect("DKG produced share for every trustee");
            let s = trustee_share.value;
            let share_point = s * aggregate_pad;
            let pub_share = s * basepoint();

            let g = basepoint();
            let context = cp_context_for_test(BINDING_CONTEXT, trustee_id_str, contest_id);
            let cp = ChaumPedersenProof::prove(
                &g,
                &aggregate_pad,
                &pub_share,
                &share_point,
                &s,
                &context,
                &mut rng,
            );

            partial_decryptions.push(PartialDecryption {
                version: WIRE_VERSION,
                trustee_id: trustee_id_str.clone(),
                share: compress_point(&share_point).to_vec(),
                proof: Some(cp.to_wire()),
            });
        }
    }

    // -- published tally -------------------------------------------------

    let tally = TallyResult {
        version: WIRE_VERSION,
        election_id: parameters.election_id.clone(),
        totals: plaintext_tallies,
        partial_decryptions: partial_decryptions.clone(),
    };

    ElectionFixture {
        parameters,
        dkg_transcript,
        ballots,
        partial_decryptions,
        tally,
        issuer_public_key: issuer_pk,
    }
}

/// Per-(voter, contest) choice. Picked so the tally is non-trivial and the
/// two contests have different totals (catches off-by-one or contest-mixing
/// bugs in the auditor).
fn voter_choice(voter_idx: usize, contest_idx: usize) -> u8 {
    match (voter_idx, contest_idx) {
        // Contest 0: voters 0, 2, 4 vote yes -> total 3
        (v, 0) if v % 2 == 0 => 1,
        (_, 0) => 0,
        // Contest 1: voters 0, 1 vote yes -> total 2
        (0, 1) => 1,
        (1, 1) => 1,
        (_, 1) => 0,
        _ => 0,
    }
}

// Re-export the joint public key as an `elgamal::PublicKey` helper for tests
// that want to encrypt extra ciphertexts under the same key.
#[allow(dead_code)]
pub(crate) fn joint_public_key_from_transcript(transcript: &DKGTranscript) -> PublicKey {
    let mut joint = RistrettoPoint::identity();
    for commit in &transcript.trustee_commitments {
        let bytes: [u8; 32] = commit.coefficient_commitments[0]
            .as_slice()
            .try_into()
            .unwrap();
        joint += saksi_crypto::group::point_from_compressed(bytes).unwrap();
    }
    elgamal::PublicKey::from_point(joint)
}
