//! One position's ballot record, built the way the generator's `build_record`
//! (saksi-auditor `fixtures.rs`) builds it: present the credential for the
//! position (per-position nullifier), encrypt one bit per candidate slot under
//! the joint key with a CDS 0-or-1 proof bound to the nullifier, then prove the
//! slots sum to exactly one.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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
    /// `BC-XXXX-XXXX`, the first 8 hex digits of the nullifier.
    pub tracking_code: String,
}

/// Builds one ballot record. Refuses a credential the election's issuer did
/// not sign, a transcript that is not the election's, an unknown position and
/// a choice outside the position's candidates.
pub fn build_ballot(
    req: &BallotRequest,
    rng: &mut (impl RngCore + CryptoRng),
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
        let context = binding_context(election_id, contest_id.as_bytes(), &nullifier);
        let proof = CDSProof::prove(&public_key, &ct, &choice_set, bit, &r, &context, rng)
            .map_err(|e| format!("CDS prove for {contest_id}: {e}"))?;
        r.zeroize();
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
    Ok(BallotResponse {
        ballot: codec::message_hex(&ballot),
        election_id: params.election_id,
        position_id: req.position_id.clone(),
        contest_ids: contests,
        tracking_code: tracking_code(&nullifier),
        nullifier: hex::encode(&nullifier),
    })
}
