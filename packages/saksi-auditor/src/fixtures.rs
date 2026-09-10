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

use std::time::{Duration, Instant};

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand_core::{CryptoRng, OsRng, RngCore};

use saksi_credentials::{
    issuer_pre_sign, issuer_sign, voter_begin_issuance, voter_blind_challenge,
    voter_finalize_issuance, Credential, IssuerPublicKey, IssuerSecretKey,
};
use saksi_crypto::{
    dkg::{run_in_memory, Dealer, DkgConfig, TrusteeShare},
    elgamal::{self, encrypt, Plaintext, PublicKey},
    group::{basepoint, compress_point},
    nizk::{cds::CDSProof, chaum_pedersen::ChaumPedersenProof, schnorr::SchnorrProof},
};
use saksi_protocol::{
    Ballot, Ciphertext as WireCiphertext, DKGTranscript, ElectionParameters, PartialDecryption,
    TallyResult, TrusteeSignature, WIRE_VERSION,
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
        signatures: sign_tally(
            &parameters.election_id,
            &plaintext_tallies,
            &trustee_ids,
            &dkg_output.trustee_shares,
            &mut rng,
        ),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionProfile {
    /// Even spread of selections across the candidate set.
    Uniform,
    /// Biased toward the first candidate (~half the votes), the rest spread.
    Skewed,
    /// Strictly decreasing vote counts, with a different shape per position.
    ///
    /// `Uniform` divides the electorate evenly and `Skewed` divides the losing
    /// half evenly, so under both profiles candidates tie: uniform ties at rank
    /// one, and skewed leaves every loser on an identical count at every
    /// population size. Neither can decide a single-winner race outright or cut
    /// cleanly at rank N for a multi-seat one.
    ///
    /// This profile apportions each position by an integer weight curve whose
    /// steepness varies with the position, then adds a one-vote ladder that
    /// makes the counts strictly decreasing by construction. A clear winner
    /// therefore holds at every voter count, and no two positions carry the
    /// same multiset of totals.
    Realistic,
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

/// Per-position vote quotas for [`SelectionProfile::Realistic`].
///
/// Returns `candidates` counts that sum to **exactly** `voters`, with a clear
/// winner always and every rank distinct once the electorate can afford it.
///
/// The shape stays deliberately close to `Skewed`, because the only thing wrong
/// with `Skewed` was the ties. Most of the electorate votes by that same rule,
/// unchanged; a reserved slice is then apportioned by a simple descending
/// weight `w_k = C - k`, which separates the candidates the round-robin had left
/// level with one another.
///
/// The reserved share widens with the position (10%, 15%, 20%), so the three
/// races come out with genuinely different spreads instead of the same multiset
/// of totals in a different order.
///
/// All of it is integer arithmetic. Floating point would be a reproducibility
/// hazard here: a last-bit difference between x86 and Apple Silicon could flip
/// an apportionment and produce a different population on a different machine,
/// which is exactly the property this generator promises not to have.
pub(crate) fn realistic_quotas(voters: usize, candidates: usize, p: usize) -> Vec<usize> {
    let c = candidates;
    if c == 0 {
        return Vec::new();
    }

    // The reserved slice must be at least C(C+1) — two per adjacent rank — or
    // the spread would be finer than the round-robin's own one-vote wobble and
    // could leave two candidates level anyway.
    let pct = 10 + 5 * (p % 3);
    let reserve = (voters * pct / 100).max(c * (c + 1)).min(voters);
    let base_voters = voters - reserve;

    // Everyone outside the reserved slice votes by the existing skewed rule,
    // untouched — this is what keeps the distribution recognisably the old one.
    let mut q = vec![0usize; c];
    for v in 0..base_voters {
        q[select_candidate(SelectionProfile::Skewed, v, p, c)] += 1;
    }

    // Apportion the reserved slice down the ranks.
    let w: Vec<usize> = (0..c).map(|k| c - k).collect();
    let total: usize = w.iter().sum();
    let mut a: Vec<usize> = w.iter().map(|&x| reserve * x / total).collect();
    let assigned: usize = a.iter().sum();
    for k in 0..(reserve - assigned) {
        a[k % c] += 1;
    }
    for k in 0..c {
        q[k] += a[k];
    }

    // A race must produce a winner even when the electorate is too small for
    // the apportionment to separate the top two. Moving one vote up from the
    // lowest-ranked candidate holding any is enough, and keeps the sum exact.
    if c > 1 && q[0] <= q[1] {
        for k in (1..c).rev() {
            if q[k] > 0 {
                q[k] -= 1;
                q[0] += 1;
                break;
            }
        }
    }
    q
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// A stride coprime to the voter count, so multiplying by it permutes the voters
/// rather than colliding them. Without it the quota brackets would hand the
/// first block of voters to candidate 0, the next block to candidate 1, and the
/// exported ballot table would read as sorted runs instead of an electorate.
fn interleave_stride(voters: usize) -> usize {
    if voters <= 2 {
        return 1;
    }
    // Golden-ratio stride: consecutive voters land far apart across the whole
    // range (a low-discrepancy sequence), so the exported table reads as a
    // mixed electorate. Step up until it is coprime with the voter count, which
    // is what keeps the multiply a permutation rather than a collision — and
    // therefore leaves the quota counts exactly intact.
    let mut s = (voters * 61803 / 100000).max(1);
    let mut tries = 0;
    while gcd(s, voters) != 1 && tries <= voters {
        s += 1;
        if s >= voters {
            s = 1;
        }
        tries += 1;
    }
    s.max(1)
}

/// Precomputed selection state, built once per generation run.
///
/// [`SelectionProfile::Realistic`] needs the quotas for a whole position before
/// it can place a single voter, so recomputing them per voter would be
/// `O(V·C log C)` — untenable at the 3.5M tier. The plan computes each
/// position's cumulative brackets once and answers a voter with a binary search.
///
/// Both generator paths build this from the same parameters, which is what keeps
/// the cryptographic stream and the ground-truth tables describing one and the
/// same population.
pub(crate) struct SelectionPlan {
    profile: SelectionProfile,
    candidates: usize,
    voters: usize,
    /// `cum[p][k]` = quotas `0..=k` summed. Empty for the non-quota profiles.
    cum: Vec<Vec<usize>>,
    stride: usize,
}

impl SelectionPlan {
    pub(crate) fn new(
        profile: SelectionProfile,
        voters: usize,
        positions: usize,
        candidates: usize,
    ) -> Self {
        let mut cum = Vec::new();
        if profile == SelectionProfile::Realistic && candidates > 1 {
            for p in 0..positions {
                let q = realistic_quotas(voters, candidates, p);
                let mut running = 0usize;
                cum.push(
                    q.iter()
                        .map(|n| {
                            running += n;
                            running
                        })
                        .collect(),
                );
            }
        }
        Self {
            profile,
            candidates,
            voters,
            cum,
            stride: interleave_stride(voters),
        }
    }

    /// Which candidate voter `voter_idx` picks for position `p`.
    pub(crate) fn select(&self, voter_idx: usize, p: usize) -> usize {
        if self.candidates <= 1 {
            return 0;
        }
        match self.profile {
            SelectionProfile::Uniform | SelectionProfile::Skewed => {
                select_candidate(self.profile, voter_idx, p, self.candidates)
            }
            SelectionProfile::Realistic => {
                let cum = &self.cum[p % self.cum.len()];
                let r = (voter_idx.wrapping_mul(self.stride) + p) % self.voters;
                // The first bracket strictly greater than r owns this voter.
                cum.partition_point(|&c| c <= r).min(self.candidates - 1)
            }
        }
    }
}

/// Deterministic 1-of-C selection under a fixed profile (reproducible).
///
/// `pub(crate)` so the ground-truth CSV writer can replay the same selections
/// without running the cryptographic generator (see `ground_truth.rs`). It is a
/// pure function of its arguments, so replaying it is bit-identical to what
/// `multi_position_fixture` records.
///
/// Handles the two position-independent profiles. [`SelectionProfile::Realistic`]
/// depends on the voter count, so it is served by [`SelectionPlan`] instead.
pub(crate) fn select_candidate(
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
        // Quota-based and voter-count dependent; see SelectionPlan::select.
        SelectionProfile::Realistic => unreachable!("Realistic is served by SelectionPlan"),
    }
}

/// Per-voter CPU time, summed by the chunked generator into `gen-timings.json`.
/// Thread-local while a voter is built, then folded into the run totals — so
/// these are CPU sums across worker threads, never wall time.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CpuTimes {
    /// Blind-signature issuance + this voter's credential presentations.
    pub(crate) credential: Duration,
    /// ElGamal encryption of every (position, candidate) bit.
    pub(crate) encrypt: Duration,
    /// CDS OR-proof generation for the same ciphertexts.
    pub(crate) cds_prove: Duration,
}

impl CpuTimes {
    /// Folds another thread's totals into this one.
    pub(crate) fn add(&mut self, other: &CpuTimes) {
        self.credential += other.credential;
        self.encrypt += other.encrypt;
        self.cds_prove += other.cds_prove;
    }
}

/// Everything a generation run computes **once**, before any voter is built:
/// election parameters, the DKG transcript + trustee shares, the issuer
/// keypair, and the selection plan.
///
/// The chunked stream writer keeps one of these alive across every chunk and
/// shares it (read-only) with the rayon workers; [`multi_position_fixture`]
/// builds one, walks the voters serially, and throws it away. Both paths run the
/// same [`build_voter`], which is what makes them one generator rather than two.
pub(crate) struct GenPrologue {
    pub(crate) parameters: ElectionParameters,
    pub(crate) dkg_transcript: DKGTranscript,
    pub(crate) issuer_public_key: IssuerPublicKey,
    election_public_key: PublicKey,
    issuer_secret_key: IssuerSecretKey,
    trustee_shares: Vec<TrusteeShare>,
    plan: SelectionPlan,
}

/// One voter's contribution: their per-position ballot records (in position
/// order), the selections behind them, this voter's per-contest ciphertext pads
/// for the running homomorphic aggregate, and the CPU spent producing them.
pub(crate) struct VoterWork {
    pub(crate) ballots: Vec<Ballot>,
    pub(crate) selections: Vec<(usize, usize)>,
    /// `pads[p * candidates + k]` — this voter's pad for that contest slot. Kept
    /// as a decompressed point so the aggregate never re-decompresses the wire
    /// bytes it just wrote.
    pub(crate) pads: Vec<RistrettoPoint>,
    pub(crate) cpu: CpuTimes,
}

/// Builds the run-wide prologue (see [`GenPrologue`]). Panics on dimensions the
/// fail-closed parameter gate would already have rejected.
pub(crate) fn gen_prologue(params: &GenParams) -> GenPrologue {
    assert!(
        params.voters >= 1 && params.positions >= 1 && params.candidates >= 1,
        "the generator needs non-empty dimensions"
    );
    assert!(
        params.threshold >= 1 && params.threshold <= params.trustees,
        "the generator needs 1 <= threshold <= trustees"
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
    let mut contest_ids: Vec<String> = Vec::with_capacity(params.positions * params.candidates);
    for p in 0..params.positions {
        for k in 0..params.candidates {
            contest_ids.push(format!("{}/cand{k}", ph_position_id(p)));
        }
    }
    let parameters = ElectionParameters {
        version: WIRE_VERSION,
        election_id: params.election_id.clone(),
        contest_ids,
        trustee_ids,
        threshold: params.threshold as u32,
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

    // -- issuer keypair ----------------------------------------------------

    let issuer_secret_key = IssuerSecretKey::generate(&mut rng);
    let issuer_public_key = issuer_secret_key.public_key();

    GenPrologue {
        parameters,
        dkg_transcript,
        issuer_public_key,
        election_public_key: dkg_output.public_key,
        issuer_secret_key,
        trustee_shares: dkg_output.trustee_shares,
        plan: SelectionPlan::new(
            params.profile,
            params.voters,
            params.positions,
            params.candidates,
        ),
    }
}

/// Builds one voter end-to-end: issue a credential, then for each position
/// present it (per-position nullifier) and encrypt + CDS-prove one bit per
/// candidate (ADR-0007 one-record-per-position).
///
/// Depends only on `pro`, `params`, `voter_idx` and its own `OsRng`, so many
/// threads can run it at once — which is what the chunked writer does inside a
/// chunk.
pub(crate) fn build_voter(pro: &GenPrologue, params: &GenParams, voter_idx: usize) -> VoterWork {
    let mut rng = OsRng;
    let candidates = params.candidates;
    let contest_count = params.positions * candidates;
    let choice_set = [Scalar::ZERO, Scalar::ONE];
    let mut cpu = CpuTimes::default();

    let started = Instant::now();
    let (request, blind_state) = voter_begin_issuance(&mut rng);
    let (pre_sig, session) = issuer_pre_sign(&pro.issuer_secret_key, &request, &mut rng);
    let (blinded, finalize_state) =
        voter_blind_challenge(blind_state, &pre_sig, &pro.issuer_public_key, &mut rng);
    let response = issuer_sign(&pro.issuer_secret_key, session, &blinded);
    let credential = voter_finalize_issuance(finalize_state, &response, &pro.issuer_public_key)
        .expect("issuance happy path");
    cpu.credential += started.elapsed();

    let mut ballots = Vec::with_capacity(params.positions);
    let mut selections = Vec::with_capacity(params.positions);
    let mut pads = vec![RistrettoPoint::identity(); contest_count];

    for p in 0..params.positions {
        let position_id = ph_position_id(p);
        // Deterministic 1-of-C selection under the chosen profile.
        let selected = pro.plan.select(voter_idx, p);
        selections.push((p, selected));

        let started = Instant::now();
        let presentation = credential.present(
            &pro.issuer_public_key,
            pro.parameters.election_id.as_bytes(),
            position_id.as_bytes(),
            BINDING_CONTEXT,
            &mut rng,
        );
        cpu.credential += started.elapsed();
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

            let started = Instant::now();
            let r = Scalar::random(&mut rng);
            let plaintext = Plaintext::from_small_integer(choice as u64);
            let ct = encrypt(&pro.election_public_key, plaintext, r);
            cpu.encrypt += started.elapsed();
            let (pad_bytes, data_bytes) = ct.to_compressed_bytes();
            ciphertexts.push(WireCiphertext {
                version: WIRE_VERSION,
                pad: pad_bytes.to_vec(),
                data: data_bytes.to_vec(),
            });
            pads[global_c] = ct.pad;

            let context = cds_context_for_test(
                pro.parameters.election_id.as_bytes(),
                pro.parameters.contest_ids[global_c].as_bytes(),
                &nullifier_bytes,
            );
            let started = Instant::now();
            let cds = CDSProof::prove(
                &pro.election_public_key,
                &ct,
                &choice_set,
                choice as usize,
                &r,
                &context,
                &mut rng,
            )
            .expect("CDS prove ok");
            cpu.cds_prove += started.elapsed();
            proofs.push(cds.to_wire());
        }

        ballots.push(Ballot {
            version: WIRE_VERSION,
            election_id: pro.parameters.election_id.clone(),
            voter_credential_commitment: presentation.credential_commitment.clone(),
            ciphertexts,
            well_formedness_proofs: proofs,
            credential_presentation: Some(presentation),
            position_id,
        });
    }

    VoterWork {
        ballots,
        selections,
        pads,
        cpu,
    }
}

/// Runs the trustee ceremony over a finished per-contest aggregate: one
/// Chaum-Pedersen-proved [`PartialDecryption`] per (contest, trustee).
///
/// Takes only the aggregate pads, never the ballots — so the chunked writer can
/// call it after streaming every ballot to disk and dropping it.
pub(crate) fn build_partial_decryptions(
    pro: &GenPrologue,
    aggregate_pads: &[RistrettoPoint],
) -> Vec<PartialDecryption> {
    let mut rng = OsRng;
    let g = basepoint();
    let trustee_ids = &pro.parameters.trustee_ids;
    let mut out = Vec::with_capacity(pro.parameters.contest_ids.len() * trustee_ids.len());

    for (c, contest_id) in pro.parameters.contest_ids.iter().enumerate() {
        let aggregate_pad = aggregate_pads[c];
        for (t, trustee_id_str) in trustee_ids.iter().enumerate() {
            let trustee_share: &TrusteeShare = pro
                .trustee_shares
                .iter()
                .find(|s| s.trustee_id == t + 1)
                .expect("DKG produced share for every trustee");
            let s = trustee_share.value;
            let share_point = s * aggregate_pad;
            let pub_share = s * basepoint();

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

            out.push(PartialDecryption {
                version: WIRE_VERSION,
                trustee_id: trustee_id_str.clone(),
                share: compress_point(&share_point).to_vec(),
                proof: Some(cp.to_wire()),
                contest_id: contest_id.clone(),
            });
        }
    }
    out
}

/// Every trustee's Schnorr signature over the published totals, in trustee
/// order (see [`crate::tally::tally_sig_context`] for the signed bytes and
/// [`crate::dkg::trustee_verification_key`] for the key that verifies them).
///
/// Production signing uses `OsRng`; only the golden-vector test passes a
/// deterministic `rng`.
pub(crate) fn sign_tally(
    election_id: &str,
    totals: &[u64],
    trustee_ids: &[String],
    trustee_shares: &[TrusteeShare],
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<TrusteeSignature> {
    let g = basepoint();
    let context = crate::tally::tally_sig_context(election_id, totals);
    trustee_ids
        .iter()
        .enumerate()
        .map(|(t, trustee_id)| {
            let share = trustee_shares
                .iter()
                .find(|s| s.trustee_id == t + 1)
                .expect("DKG produced share for every trustee");
            let public_share = share.value * g;
            let proof = SchnorrProof::prove(&g, &public_share, &share.value, &context, rng);
            TrusteeSignature {
                trustee_id: trustee_id.clone(),
                signature: proof.to_bytes().to_vec(),
            }
        })
        .collect()
}

/// Assembles the published [`TallyResult`] from the seeded totals + the
/// ceremony, signed by every trustee.
pub(crate) fn build_tally(
    pro: &GenPrologue,
    totals: Vec<u64>,
    partial_decryptions: Vec<PartialDecryption>,
) -> TallyResult {
    let signatures = sign_tally(
        &pro.parameters.election_id,
        &totals,
        &pro.parameters.trustee_ids,
        &pro.trustee_shares,
        &mut OsRng,
    );
    TallyResult {
        version: WIRE_VERSION,
        election_id: pro.parameters.election_id.clone(),
        totals,
        partial_decryptions,
        signatures,
    }
}

/// Synthetic voter id for ballot record `ballot_idx` when each voter casts
/// `positions` records. Ballots are voter-major, so the id is a pure function of
/// the index and no per-ballot table has to be carried through generation.
pub(crate) fn voter_id_for_ballot(ballot_idx: usize, positions: usize) -> String {
    format!("voter-{}", ballot_idx / positions.max(1))
}

pub(crate) fn multi_position_fixture(params: &GenParams) -> ElectionFixture {
    let pro = gen_prologue(params);
    let contest_count = params.positions * params.candidates;

    let mut ballots: Vec<Ballot> = Vec::with_capacity(params.voters * params.positions);
    // Recorded selections drive the INDEPENDENT ground-truth tally (see
    // `tally_selections`) — never accumulated inline with the ciphertexts.
    let mut selections: Vec<(usize, usize)> = Vec::with_capacity(params.voters * params.positions);
    let mut aggregate_pads = vec![RistrettoPoint::identity(); contest_count];

    for voter_idx in 0..params.voters {
        let work = build_voter(&pro, params, voter_idx);
        for (c, pad) in work.pads.iter().enumerate() {
            aggregate_pads[c] += pad;
        }
        selections.extend(work.selections);
        ballots.extend(work.ballots);
    }

    // Synthetic voter id: shared across this voter's positions, unique per voter
    // (paper Table 3.1). Off-wire generation metadata.
    let voter_ids = (0..ballots.len())
        .map(|i| voter_id_for_ballot(i, params.positions))
        .collect();

    // -- independent ground truth (NOT accumulated in the crypto loop) ------
    let ground_truth = tally_selections(&selections, contest_count, params.candidates);
    let partial_decryptions = build_partial_decryptions(&pro, &aggregate_pads);
    let tally = build_tally(&pro, ground_truth.clone(), partial_decryptions.clone());

    ElectionFixture {
        parameters: pro.parameters,
        dkg_transcript: pro.dkg_transcript,
        ballots,
        partial_decryptions,
        tally,
        issuer_public_key: pro.issuer_public_key,
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

#[cfg(test)]
mod realistic_profile_tests {
    use super::*;

    /// The parameter space the generator is actually driven over: every wizard
    /// preset boundary plus the small counts where the strict-ordering budget
    /// runs out.
    const VOTERS: &[usize] = &[1, 2, 3, 5, 6, 7, 20, 65, 66, 100, 1000, 10_000, 3_524_078];
    const CANDIDATES: &[usize] = &[2, 3, 4, 6, 12, 37];

    #[test]
    fn quotas_sum_to_exactly_the_electorate() {
        // Every voter votes, once, in every position. A quota set that does not
        // sum to the voter count would invent or lose votes before any
        // cryptography ran.
        for &v in VOTERS {
            for &c in CANDIDATES {
                for p in 0..4 {
                    let q = realistic_quotas(v, c, p);
                    assert_eq!(q.len(), c, "V={v} C={c} p={p}: wrong candidate count");
                    assert_eq!(
                        q.iter().sum::<usize>(),
                        v,
                        "V={v} C={c} p={p}: quotas {q:?} do not sum to the electorate"
                    );
                }
            }
        }
    }

    #[test]
    fn there_is_always_a_clear_winner() {
        // The property the profile exists for: a single-winner race must never
        // come down to a tie at the top, at any population size.
        for &v in VOTERS {
            for &c in CANDIDATES {
                for p in 0..4 {
                    let q = realistic_quotas(v, c, p);
                    assert!(
                        q[0] > q[1],
                        "V={v} C={c} p={p}: top two tied at {} — no clear winner ({q:?})",
                        q[0]
                    );
                }
            }
        }
    }

    #[test]
    fn counts_strictly_decrease_once_the_electorate_can_afford_it() {
        // Ranks separate once the reserved slice is large enough to spread
        // them. Measured, that happens by V = 8 at 4 candidates, 72 at 12 and
        // 684 at 37; the reserve floor C(C+1) sits above all three, so it is a
        // safe bound to assert from.
        for &c in CANDIDATES {
            let floor = c * (c + 1);
            for &v in VOTERS {
                if v < floor {
                    continue;
                }
                for p in 0..4 {
                    let q = realistic_quotas(v, c, p);
                    for k in 0..c - 1 {
                        assert!(
                            q[k] > q[k + 1],
                            "V={v} C={c} p={p}: rank {k} and {} both hold {} ({q:?})",
                            k + 1,
                            q[k]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn positions_usually_differ_but_it_is_not_guaranteed() {
        // Each position reserves a different share (10/15/20%), so the three
        // races normally come out with different totals — but this design does
        // NOT guarantee it. At some voter counts the different reserves happen
        // to land on the same multiset, at every candidate count, scattered
        // rather than below a threshold.
        //
        // Recorded as a measured fact rather than asserted as a property: the
        // contest-mixing limitation is therefore NOT closed by this profile.
        // A component that confused one contest for another could still satisfy
        // E = 0 on an unlucky configuration. Guaranteeing distinct shapes needs
        // a per-position weight curve, which is materially more code.
        let c = 12;
        let mut collisions = 0;
        let mut total = 0;
        for v in 216..1200 {
            total += 1;
            let mut shapes: Vec<Vec<usize>> = (0..3)
                .map(|p| {
                    let mut q = realistic_quotas(v, c, p);
                    q.sort_unstable();
                    q
                })
                .collect();
            shapes.sort();
            shapes.dedup();
            if shapes.len() < 3 {
                collisions += 1;
            }
        }
        // Measured: 85 of 984 configurations collide, about 8.6%. The bound is
        // set well above that so it does not go off on a rounding change, but
        // far below "always" — it exists to catch a regression to three
        // identical races, not to police the exact rate.
        assert!(
            collisions * 5 < total,
            "positions collided in {collisions}/{total} configurations —              the races would read as duplicates of one another"
        );
    }

    #[test]
    fn the_plan_realizes_its_quotas_exactly() {
        // The stride permutes voters across the quota brackets; if it ever
        // collided instead, the realized counts would drift from the quotas and
        // the ground truth would stop matching what was planned.
        for &v in &[1usize, 7, 20, 100, 1000, 5000] {
            for &c in &[2usize, 4, 12] {
                let positions = 3;
                let plan = SelectionPlan::new(SelectionProfile::Realistic, v, positions, c);
                for p in 0..positions {
                    let mut got = vec![0usize; c];
                    for voter in 0..v {
                        got[plan.select(voter, p)] += 1;
                    }
                    let want = realistic_quotas(v, c, p);
                    assert_eq!(got, want, "V={v} C={c} p={p}: realized counts != quotas");
                }
            }
        }
    }

    #[test]
    fn existing_profiles_are_untouched() {
        // uniform and skewed back the manuscript's RQ comparisons; this change
        // must not move them.
        let c = 4;
        let uniform: Vec<usize> = (0..8)
            .map(|v| select_candidate(SelectionProfile::Uniform, v, 0, c))
            .collect();
        assert_eq!(uniform, vec![0, 1, 2, 3, 0, 1, 2, 3]);
        let skewed: Vec<usize> = (0..8)
            .map(|v| select_candidate(SelectionProfile::Skewed, v, 0, c))
            .collect();
        assert_eq!(skewed, vec![0, 1, 0, 2, 0, 3, 0, 1]);
    }

    #[test]
    fn a_single_candidate_contest_is_still_trivially_valid() {
        let plan = SelectionPlan::new(SelectionProfile::Realistic, 10, 2, 1);
        for v in 0..10 {
            assert_eq!(plan.select(v, 0), 0);
        }
    }
}

/// Cross-language golden vector for the trustee tally signature.
///
/// The Go chaincode (Task 11) reads `test-vectors/tally-sig-v1.hex` and must
/// derive the same verification keys and accept the same signatures, so this
/// module pins the bytes. Layout, one item per line:
///
/// ```text
/// 1           dkg_transcript, hex of the canonical protobuf encoding
/// 2           election_id, hex of its UTF-8 bytes
/// 3           trustee_ids, comma-separated, in ElectionParameters order
/// 4           totals, comma-separated decimal, in contest order
/// 5           threshold, decimal
/// 6..6+n      trustee_id,verification_key_hex,signature_hex  (trustee order)
/// last        negative,trustee_id,verification_key_hex,signature_hex
/// ```
///
/// The trustee ids are deliberately **non-numeric and not in sorted order**: a
/// port that derives the share index by parsing the id (or by sorting) instead
/// of taking its 1-based position in the `trustee_ids` line must fail this
/// vector rather than pass it by coincidence.
///
/// The `negative` line is a well-formed signature by the first trustee over
/// *different* totals: a verifier that forgets to bind the totals into the
/// context accepts it, and is wrong.
///
/// Regenerate with `SAKSI_WRITE_VECTORS=1 cargo test -p saksi-auditor
/// tally_signature_golden_vector`.
#[cfg(test)]
mod tally_signature_vector {
    use std::path::PathBuf;

    use super::*;
    use crate::dkg::{decode_trustee_commitments, trustee_verification_key};
    use crate::tally::tally_sig_context;
    use saksi_crypto::group::point_from_compressed;
    use saksi_protocol::encode;

    /// SplitMix64 as an `RngCore`: deterministic, so the vector's signatures are
    /// byte-stable. **Vector-only** — every production signing path (see
    /// [`build_tally`]) uses `OsRng`.
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

    const ELECTION_ID: &str = "election-2026";
    /// Opaque trustee labels: non-numeric and NOT in sorted order, so the only
    /// way to reach the right DKG share index is the 1-based position in this
    /// list (see [`crate::dkg::trustee_verification_key`]).
    const TRUSTEE_IDS: [&str; 5] = [
        "trustee-e",
        "trustee-a",
        "trustee-d",
        "trustee-b",
        "trustee-c",
    ];
    const TOTALS: [u64; 2] = [4, 2];
    /// The totals the `negative` line signs instead of [`TOTALS`].
    const OTHER_TOTALS: [u64; 2] = [5, 1];

    /// The fixed 3-of-5 DKG the vector is built on: the same deterministic
    /// dealer polynomials [`happy_path_fixture`] uses, so the vector's keys are
    /// the fixture's keys.
    fn vector_dkg() -> (DKGTranscript, Vec<TrusteeShare>, Vec<String>, u32) {
        let config = DkgConfig::default_3_of_5();
        let dealers: Vec<Dealer> = (1..=config.trustees)
            .map(|dealer_id| {
                Dealer::new(
                    dealer_id,
                    (0..config.threshold)
                        .map(|coefficient| Scalar::from((dealer_id * 10 + coefficient + 1) as u64))
                        .collect(),
                )
            })
            .collect();
        let output = run_in_memory(config, &dealers).expect("DKG completes");
        let transcript = output.to_protocol_transcript(ELECTION_ID);
        let trustee_ids = TRUSTEE_IDS.iter().map(|id| id.to_string()).collect();
        (
            transcript,
            output.trustee_shares,
            trustee_ids,
            config.threshold as u32,
        )
    }

    fn vector_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../saksi-protocol/test-vectors/tally-sig-v1.hex")
    }

    fn proof_from_hex(hex_str: &str) -> SchnorrProof {
        let bytes: [u8; 64] = hex::decode(hex_str)
            .expect("signature hex")
            .try_into()
            .expect("64-byte signature");
        SchnorrProof::from_bytes(&bytes).expect("canonical Schnorr proof")
    }

    /// The signed bytes are exactly the domain, the election id, and the totals
    /// as little-endian u64s — no length prefixes. Hand-computed, so a change to
    /// the encoding cannot slip through by regenerating the vector.
    #[test]
    fn tally_sig_context_is_domain_election_id_and_le_totals() {
        assert_eq!(
            hex::encode(tally_sig_context("e1", &[1, 258])),
            concat!(
                "73616b73692e74616c6c792e7369672e7631", // b"saksi.tally.sig.v1"
                "6531",                                 // b"e1"
                "0100000000000000",                     // 1u64, little-endian
                "0201000000000000",                     // 258u64, little-endian
            )
        );
    }

    /// The key derived from the public transcript alone is the trustee's real
    /// public share `s_i·G` — which is what lets anyone holding only the
    /// bulletin board check the signature.
    #[test]
    fn derived_verification_keys_equal_share_publics() {
        let (transcript, shares, trustee_ids, _) = vector_dkg();
        let commitments = decode_trustee_commitments(&transcript).expect("transcript decodes");
        for t in 0..trustee_ids.len() {
            let share = shares
                .iter()
                .find(|s| s.trustee_id == t + 1)
                .expect("share per trustee");
            assert_eq!(
                trustee_verification_key(&commitments, (t + 1) as u64),
                share.value * basepoint(),
                "trustee {} verification key must equal s_i·G",
                t + 1
            );
        }
    }

    /// Renders the vector text (deterministic) and pins it against the committed
    /// file, then reads that file back and verifies every line the way the Go
    /// chaincode will.
    #[test]
    fn tally_signature_golden_vector() {
        let (transcript, shares, trustee_ids, threshold) = vector_dkg();
        let mut rng = SplitMix64(0x5AC5_1000_0000_0001);

        let signatures = sign_tally(ELECTION_ID, &TOTALS, &trustee_ids, &shares, &mut rng);
        let negative = sign_tally(
            ELECTION_ID,
            &OTHER_TOTALS,
            &trustee_ids[..1],
            &shares,
            &mut rng,
        );
        let commitments = decode_trustee_commitments(&transcript).expect("transcript decodes");

        let mut lines = vec![
            hex::encode(encode(&transcript)),
            hex::encode(ELECTION_ID.as_bytes()),
            trustee_ids.join(","),
            TOTALS
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            threshold.to_string(),
        ];
        for (t, signature) in signatures.iter().enumerate() {
            lines.push(format!(
                "{},{},{}",
                signature.trustee_id,
                hex::encode(compress_point(&trustee_verification_key(
                    &commitments,
                    (t + 1) as u64
                ))),
                hex::encode(&signature.signature),
            ));
        }
        lines.push(format!(
            "negative,{},{},{}",
            negative[0].trustee_id,
            hex::encode(compress_point(&trustee_verification_key(&commitments, 1))),
            hex::encode(&negative[0].signature),
        ));
        let rendered = format!("{}\n", lines.join("\n"));

        let path = vector_path();
        if std::env::var_os("SAKSI_WRITE_VECTORS").is_some() {
            std::fs::write(&path, &rendered).expect("write golden vector");
        }
        let committed = std::fs::read_to_string(&path)
            .expect("golden vector is committed")
            .replace("\r\n", "\n");
        assert_eq!(
            committed, rendered,
            "tally-signature golden vector drifted; the Go cross-check must be regenerated too"
        );

        // -- round-trip: verify the committed file the way Go will ------------

        let read: Vec<&str> = committed.lines().collect();
        let transcript: DKGTranscript =
            saksi_protocol::decode(&hex::decode(read[0]).expect("transcript hex"))
                .expect("transcript decodes");
        let election_id =
            String::from_utf8(hex::decode(read[1]).expect("election id hex")).expect("utf-8");
        let ids: Vec<&str> = read[2].split(',').collect();
        let totals: Vec<u64> = read[3]
            .split(',')
            .map(|t| t.parse().expect("total"))
            .collect();
        let threshold: usize = read[4].parse().expect("threshold");

        // The ids must be useless as indices: a port that does `atoi(id)` or
        // sorts them cannot reproduce the keys below.
        assert!(
            ids.iter().all(|id| id.parse::<u64>().is_err()),
            "the vector's trustee ids must be non-numeric so position is the only index: {ids:?}"
        );
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_ne!(ids, sorted, "the vector's trustee ids must not be sorted");
        let commitments = decode_trustee_commitments(&transcript).expect("transcript decodes");
        let context = tally_sig_context(&election_id, &totals);
        let g = basepoint();

        let mut verified = 0usize;
        for (t, line) in read[5..read.len() - 1].iter().enumerate() {
            let fields: Vec<&str> = line.split(',').collect();
            assert_eq!(fields[0], ids[t], "trustee order");
            // Index by POSITION in the trustee_ids line, not by the id itself.
            let key = trustee_verification_key(&commitments, (t + 1) as u64);
            assert_eq!(
                hex::encode(compress_point(&key)),
                fields[1],
                "line {} pins a key the transcript does not derive",
                t + 6
            );
            proof_from_hex(fields[2])
                .verify(&g, &key, &context)
                .unwrap_or_else(|_| panic!("trustee {} signature must verify", t + 1));
            verified += 1;
        }
        assert_eq!(verified, trustee_ids.len());
        assert!(verified >= threshold);

        // The negative line is a real signature over different totals: it must
        // NOT verify against the published totals' context.
        let fields: Vec<&str> = read[read.len() - 1].split(',').collect();
        assert_eq!(fields[0], "negative");
        let key_bytes: [u8; 32] = hex::decode(fields[2])
            .expect("key hex")
            .try_into()
            .expect("32-byte key");
        let key = point_from_compressed(key_bytes).expect("key point");
        assert!(
            proof_from_hex(fields[3])
                .verify(&g, &key, &context)
                .is_err(),
            "the negative vector must be rejected over the published totals"
        );
        assert!(
            proof_from_hex(fields[3])
                .verify(&g, &key, &tally_sig_context(&election_id, &OTHER_TOTALS))
                .is_ok(),
            "the negative vector is a real signature over the other totals"
        );
    }
}
