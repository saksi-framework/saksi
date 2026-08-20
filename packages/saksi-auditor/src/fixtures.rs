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
    /// Seeded ground-truth totals, one per contest (aligned to
    /// `parameters.contest_ids`). Computed from the cleartext choices, so a
    /// consumer can cross-check the published tally and the ballot sum against
    /// it independently (the Phase 1 validation gate + Phase 3 accuracy score).
    pub(crate) ground_truth: Vec<u64>,
    /// Synthetic voter identifier per ballot record (paper Table 3.1). Repeats
    /// across a voter's positions and is unique per voter. Generation-side
    /// metadata only — it is NOT on the wire ballot (on-chain unlinkability),
    /// but the validation gate and Appendix-A records use it.
    pub(crate) voter_ids: Vec<String>,
    /// Display-only election name (stream header metadata; not bound into any
    /// proof). Equals `election_id` for the back-compat `simple` path.
    pub(crate) election_name: String,
    /// Display-only trustee names, aligned to `parameters.trustee_ids` (stream
    /// header metadata; not on the wire). `"1".."n"` for the back-compat path.
    pub(crate) trustee_names: Vec<String>,
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
            ground_truth: Some(&self.ground_truth),
        }
    }

    /// Borrow this fixture as the **public election record only** — the same
    /// bulletin-board artifacts a third party would have, with `ground_truth`
    /// stripped (the seeded answer key is NOT public). This is what the formal
    /// independent-verification test (panel #29) audits: the verifier must
    /// reproduce and check the tally from public data alone, never against a
    /// private answer key.
    #[cfg(test)]
    pub(crate) fn public_artifacts(&self) -> ElectionArtifacts<'_> {
        ElectionArtifacts {
            ground_truth: None,
            ..self.artifacts()
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
        let mut ciphertexts: Vec<WireCiphertext> = Vec::with_capacity(contest_ids.len());
        let mut proofs = Vec::with_capacity(contest_ids.len());

        // Present the credential first so the CDS proofs can bind to the
        // ballot's nullifier (ADR-0007: the same context the chaincode
        // reconstructs on-chain at endorsement).
        // Transitional: empty position_id = per-election nullifier (the current
        // multi-contest fixture model). Phase 1's generator emits one record per
        // position, each with its own per-position nullifier.
        let presentation = credential.present(
            &issuer_pk,
            parameters.election_id.as_bytes(),
            b"",
            BINDING_CONTEXT,
            &mut rng,
        );
        let nullifier_bytes = presentation
            .nullifier
            .as_ref()
            .expect("presentation has a nullifier")
            .value
            .clone();

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
            let context = cds_context_for_test(
                parameters.election_id.as_bytes(),
                contest_id.as_bytes(),
                &nullifier_bytes,
            );
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

        ballots.push(Ballot {
            version: WIRE_VERSION,
            election_id: parameters.election_id.clone(),
            voter_credential_commitment: presentation.credential_commitment.clone(),
            ciphertexts,
            well_formedness_proofs: proofs,
            credential_presentation: Some(presentation),
            // Legacy whole-ballot fixture: empty position_id → the ballot covers
            // all contests (the pre-R2 model). The multi-position generator
            // (`multi_position_fixture`) emits one record per position instead.
            position_id: String::new(),
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
                contest_id: contest_id.clone(),
            });
        }
    }

    // -- published tally -------------------------------------------------

    let tally = TallyResult {
        version: WIRE_VERSION,
        election_id: parameters.election_id.clone(),
        totals: plaintext_tallies.clone(),
        partial_decryptions: partial_decryptions.clone(),
    };

    // Legacy fixture: one ballot per voter, so voter-i labels the i-th ballot.
    let voter_ids = (0..ballots.len()).map(|i| format!("voter-{i}")).collect();

    ElectionFixture {
        parameters,
        dkg_transcript,
        ballots,
        partial_decryptions,
        tally,
        issuer_public_key: issuer_pk,
        ground_truth: plaintext_tallies,
        voter_ids,
        election_name: "election-2026".into(),
        trustee_names: trustee_ids.clone(),
    }
}

/// Builds a parameterized multi-position election end-to-end (ADR-0007
/// one-record-per-position model): `voters` voters, `positions` positions each
/// with `candidates` candidates.
///
/// Emits **one ballot record per (voter, position)** — each carries that
/// position's `candidates` binary ciphertexts, a CDS OR-proof per candidate, and
/// a credential presentation whose nullifier is per-position
/// (`PRF(s_cred, election_id ‖ position_id)`), so double voting is prevented per
/// voter per position. `contest_ids` are position-qualified `"pos{p}/cand{k}"`
/// (P×C total). Each voter selects exactly one candidate per position
/// (deterministic, seeded), so the ground truth is well-defined and every ballot
/// is valid. `positions == 1` is the single-position ballot axis; `> 1` is
/// multi-position.
/// Candidate-selection distribution profile (paper §Appendix A: "uniform and
/// skewed profiles, fixed for reproducibility"). Both are deterministic so a
/// generated population is byte-reproducible.
#[derive(Clone, Copy, Debug)]
pub enum SelectionProfile {
    /// Even spread of selections across the candidate set.
    Uniform,
    /// Biased toward the first candidate (~half the votes), the rest spread.
    Skewed,
}

/// Full parameterization for the multi-position generator. Carries the
/// cryptographically-bound `election_id`, the display-only `election_name` +
/// `trustee_names` (surfaced in the stream header, off-wire — NOT bound into any
/// proof), the t-of-n DKG shape, and the population dimensions.
///
/// Re-exported as `saksi_auditor::demo::GenParams` so the `saksi-demo` CLI (a
/// separate crate) can construct it; the fixture module itself is `pub(crate)`.
#[derive(Clone, Debug)]
pub struct GenParams {
    /// Cryptographically-bound election identifier (nullifier + proof domain).
    pub election_id: String,
    /// Display-only election name for the stream header (not bound into proofs).
    pub election_name: String,
    /// DKG threshold `t` (`1 <= t <= trustees`).
    pub threshold: usize,
    /// DKG trustee count `n`.
    pub trustees: usize,
    /// Display-only trustee names, aligned to the `n` trustees (header metadata).
    pub trustee_names: Vec<String>,
    /// Number of voters (one credential each).
    pub voters: usize,
    /// Number of ballot positions.
    pub positions: usize,
    /// Number of candidates per position.
    pub candidates: usize,
    /// Deterministic candidate-selection distribution profile.
    pub profile: SelectionProfile,
}

impl GenParams {
    /// Back-compat constructor filling today's defaults (`election_id` +
    /// `election_name` = `"election-2026"`, 3-of-5, trustee names `"1".."5"`).
    /// Every existing caller passes only the population dimensions; the console
    /// builds a full [`GenParams`].
    pub fn simple(
        voters: usize,
        positions: usize,
        candidates: usize,
        profile: SelectionProfile,
    ) -> Self {
        Self {
            election_id: "election-2026".into(),
            election_name: "election-2026".into(),
            threshold: 3,
            trustees: 5,
            trustee_names: (1..=5u32).map(|i| i.to_string()).collect(),
            voters,
            positions,
            candidates,
            profile,
        }
    }
}

/// Philippine multi-position ballot labels (paper §3.4: President, Vice
/// President, Senator — single-winner each); generic slug beyond three.
pub(crate) fn ph_position_id(p: usize) -> String {
    match p {
        0 => "president".to_string(),
        1 => "vice-president".to_string(),
        2 => "senator".to_string(),
        n => format!("position-{n}"),
    }
}

/// Independent ground-truth tally over the recorded per-ballot selections.
///
/// Ground truth is derived HERE, from an explicit record of what each voter
/// chose — never accumulated as a side effect of the ciphertext-building loop.
/// That separation is what gives the `E = 0` accuracy check teeth: if a bug in
/// the crypto loop encrypts a different bit than the voter selected, the
/// homomorphic decrypt of the ciphertexts diverges from this independent tally
/// and `E = 0` fails, instead of both sharing the same wrong `choice` and
/// passing (eng review finding: self-reported ground truth).
///
/// Each entry is `(position_index, selected_candidate)`; it contributes `+1` to
/// contest slot `position_index * candidates + selected_candidate`.
pub(crate) fn tally_selections(
    selections: &[(usize, usize)],
    contest_count: usize,
    candidates: usize,
) -> Vec<u64> {
    let mut totals = vec![0u64; contest_count];
    for &(p, selected) in selections {
        totals[p * candidates + selected] += 1;
    }
    totals
}

/// Deterministic 1-of-C selection under a fixed profile (reproducible).
fn select_candidate(
    profile: SelectionProfile,
    voter_idx: usize,
    p: usize,
    candidates: usize,
) -> usize {
    if candidates <= 1 {
        return 0;
    }
    match profile {
        SelectionProfile::Uniform => (voter_idx + p) % candidates,
        // Half the voters pick candidate 0; the rest spread over 1..C.
        SelectionProfile::Skewed => {
            if voter_idx % 2 == 0 {
                0
            } else {
                1 + ((voter_idx / 2 + p) % (candidates - 1))
            }
        }
    }
}

pub(crate) fn multi_position_fixture(params: &GenParams) -> ElectionFixture {
    let voters = params.voters;
    let positions = params.positions;
    let candidates = params.candidates;
    let profile = params.profile;
    assert!(
        voters >= 1 && positions >= 1 && candidates >= 1,
        "multi_position_fixture needs non-empty dimensions"
    );
    assert!(
        params.threshold >= 1 && params.threshold <= params.trustees,
        "multi_position_fixture needs 1 <= threshold <= trustees"
    );
    assert_eq!(
        params.trustee_names.len(),
        params.trustees,
        "trustee_names must align with trustees"
    );
    let mut rng = OsRng;

    // -- election parameters (position-qualified contests) -----------------

    let trustee_ids: Vec<String> = (1..=params.trustees as u32)
        .map(|i| i.to_string())
        .collect();
    let threshold: u32 = params.threshold as u32;
    let mut contest_ids: Vec<String> = Vec::with_capacity(positions * candidates);
    for p in 0..positions {
        for k in 0..candidates {
            contest_ids.push(format!("{}/cand{k}", ph_position_id(p)));
        }
    }
    let parameters = ElectionParameters {
        version: WIRE_VERSION,
        election_id: params.election_id.clone(),
        contest_ids: contest_ids.clone(),
        trustee_ids: trustee_ids.clone(),
        threshold,
    };

    // -- DKG (t-of-n; deterministic dealers as happy_path) -----------------

    let config = DkgConfig::new(params.threshold, params.trustees).expect("valid t-of-n");
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

    // -- issuer + one credential per voter ---------------------------------

    let issuer_sk = IssuerSecretKey::generate(&mut rng);
    let issuer_pk = issuer_sk.public_key();
    let mut credentials: Vec<Credential> = Vec::with_capacity(voters);
    for _ in 0..voters {
        let (request, blind_state) = voter_begin_issuance(&mut rng);
        let (pre_sig, session) = issuer_pre_sign(&issuer_sk, &request, &mut rng);
        let (blinded, finalize_state) =
            voter_blind_challenge(blind_state, &pre_sig, &issuer_pk, &mut rng);
        let response = issuer_sign(&issuer_sk, session, &blinded);
        credentials.push(
            voter_finalize_issuance(finalize_state, &response, &issuer_pk)
                .expect("issuance happy path"),
        );
    }

    // -- one ballot per (voter, position); ground truth per contest --------

    let mut ballots: Vec<Ballot> = Vec::with_capacity(voters * positions);
    let mut voter_ids: Vec<String> = Vec::with_capacity(voters * positions);
    // Recorded selections drive the INDEPENDENT ground-truth tally (see
    // `tally_selections`) — never accumulated inline with the ciphertexts.
    let mut selections: Vec<(usize, usize)> = Vec::with_capacity(voters * positions);
    let choice_set = [Scalar::ZERO, Scalar::ONE];

    for (voter_idx, credential) in credentials.iter().enumerate() {
        for p in 0..positions {
            let position_id = ph_position_id(p);
            // Deterministic 1-of-C selection under the chosen profile.
            let selected = select_candidate(profile, voter_idx, p, candidates);
            selections.push((p, selected));

            let presentation = credential.present(
                &issuer_pk,
                parameters.election_id.as_bytes(),
                position_id.as_bytes(),
                BINDING_CONTEXT,
                &mut rng,
            );
            let nullifier_bytes = presentation
                .nullifier
                .as_ref()
                .expect("presentation has a nullifier")
                .value
                .clone();

            let mut ciphertexts: Vec<WireCiphertext> = Vec::with_capacity(candidates);
            let mut proofs = Vec::with_capacity(candidates);
            for k in 0..candidates {
                let global_c = p * candidates + k;
                let choice: u8 = u8::from(k == selected);

                let r = Scalar::random(&mut rng);
                let plaintext = Plaintext::from_small_integer(choice as u64);
                let ct = encrypt(&election_public_key, plaintext, r);
                let (pad_bytes, data_bytes) = ct.to_compressed_bytes();
                ciphertexts.push(WireCiphertext {
                    version: WIRE_VERSION,
                    pad: pad_bytes.to_vec(),
                    data: data_bytes.to_vec(),
                });

                let context = cds_context_for_test(
                    parameters.election_id.as_bytes(),
                    contest_ids[global_c].as_bytes(),
                    &nullifier_bytes,
                );
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

            ballots.push(Ballot {
                version: WIRE_VERSION,
                election_id: parameters.election_id.clone(),
                voter_credential_commitment: presentation.credential_commitment.clone(),
                ciphertexts,
                well_formedness_proofs: proofs,
                credential_presentation: Some(presentation),
                position_id,
            });
            // Synthetic voter id: shared across this voter's positions, unique
            // per voter (paper Table 3.1). Off-wire generation metadata.
            voter_ids.push(format!("voter-{voter_idx}"));
        }
    }

    // -- independent ground truth (NOT accumulated in the crypto loop) ------
    let ground_truth = tally_selections(&selections, contest_ids.len(), candidates);

    // -- aggregate per contest (reuse the shared position→contest mapping) --

    let contest_count = contest_ids.len();
    let trustee_count = trustee_ids.len();
    let mut aggregate_pads = vec![RistrettoPoint::identity(); contest_count];
    for ballot in &ballots {
        let idxs = crate::contest_indices_for_position(&contest_ids, &ballot.position_id);
        for (local, ct) in ballot.ciphertexts.iter().enumerate() {
            let pad: [u8; 32] = ct.pad.as_slice().try_into().unwrap();
            aggregate_pads[idxs[local]] += saksi_crypto::group::point_from_compressed(pad).unwrap();
        }
    }

    // -- one partial decryption per (contest, trustee) ---------------------

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
                contest_id: contest_id.clone(),
            });
        }
    }

    let tally = TallyResult {
        version: WIRE_VERSION,
        election_id: parameters.election_id.clone(),
        totals: ground_truth.clone(),
        partial_decryptions: partial_decryptions.clone(),
    };

    ElectionFixture {
        parameters,
        dkg_transcript,
        ballots,
        partial_decryptions,
        tally,
        issuer_public_key: issuer_pk,
        ground_truth,
        voter_ids,
        election_name: params.election_name.clone(),
        trustee_names: params.trustee_names.clone(),
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

#[cfg(test)]
mod tally_selection_tests {
    use super::*;

    #[test]
    fn tally_selections_sums_into_position_qualified_slots() {
        // 2 positions × 3 candidates = 6 contest slots.
        // Selections: p0 picks c1, c1, c0; p1 picks c2, c2.
        let selections = [(0, 1), (0, 1), (0, 0), (1, 2), (1, 2)];
        let totals = tally_selections(&selections, 6, 3);
        // p0: [c0=1, c1=2, c2=0] ; p1: [c0=0, c1=0, c2=2]
        assert_eq!(totals, vec![1, 2, 0, 0, 0, 2]);
        // Sanity: total selections == sum of totals (nothing lost/duplicated).
        assert_eq!(totals.iter().sum::<u64>(), selections.len() as u64);
    }

    #[test]
    fn ground_truth_is_independent_of_the_ciphertext_loop() {
        // The fixture's ground_truth must equal a from-scratch recount of what
        // each voter selected — proving it is derived from the recorded
        // selections, not co-produced with the ciphertexts.
        let f = multi_position_fixture(&GenParams::simple(4, 2, 3, SelectionProfile::Skewed));
        let mut recount = vec![0u64; f.parameters.contest_ids.len()];
        for voter_idx in 0..4 {
            for p in 0..2 {
                let selected = select_candidate(SelectionProfile::Skewed, voter_idx, p, 3);
                recount[p * 3 + selected] += 1;
            }
        }
        assert_eq!(
            f.ground_truth, recount,
            "ground_truth must match an independent recount of the selections"
        );
        // One selection per (voter, position): total == voters * positions.
        assert_eq!(f.ground_truth.iter().sum::<u64>(), 4 * 2);
    }

    #[test]
    fn parameterized_fixture_honors_trustees_and_name() {
        let p = GenParams {
            election_id: "midterm-2026".into(),
            election_name: "Midterm 2026".into(),
            threshold: 2,
            trustees: 3,
            trustee_names: vec!["Alice".into(), "Bob".into(), "Carol".into()],
            voters: 4,
            positions: 2,
            candidates: 2,
            profile: SelectionProfile::Uniform,
        };
        let f = multi_position_fixture(&p);
        assert_eq!(f.parameters.election_id, "midterm-2026");
        assert_eq!(f.parameters.trustee_ids.len(), 3);
        assert_eq!(f.parameters.threshold, 2);
        // one ballot per (voter, position)
        assert_eq!(f.ballots.len(), 4 * 2);
        // one partial decryption per (contest, trustee): 2 positions × 2 cand × 3
        assert_eq!(f.partial_decryptions.len(), 2 * 2 * 3);
        // display metadata carried through to the fixture (for the stream header)
        assert_eq!(f.election_name, "Midterm 2026");
        assert_eq!(f.trustee_names, vec!["Alice", "Bob", "Carol"]);
    }
}
