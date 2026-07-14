//! Per-ballot soundness checks.
//!
//! For every published [`saksi_protocol::Ballot`] this module verifies:
//!
//! 1. Wire-shape (`ciphertexts.len() == well_formedness_proofs.len() == contest_ids.len()`).
//! 2. The CDS OR-proof per contest, with `choice_set = {0, 1}` (v1: binary
//!    contests only) and `context = binding_context || contest_id || ballot_serial`.
//! 3. The credential presentation under the supplied issuer public key, bound
//!    to `election_id` and `binding_context`.
//! 4. That the embedded `issuer_public_key` field on the presentation matches
//!    the trust-anchor key passed at the artifacts boundary (single-issuer
//!    assumption for v1).
//!
//! Nullifier *uniqueness* is enforced in [`crate::lib::audit`] across the
//! whole ballot list, not here.

//! v1: binary contests only — `choice_set = {0, 1}`. Multi-choice (k >= 3)
//! contests would need either a per-contest choice set in the wire schema or
//! a per-election ballot-style descriptor; both are out of scope for the
//! demo bar.

use curve25519_dalek::scalar::Scalar;

use saksi_credentials::{verify_presentation, IssuerPublicKey};
use saksi_crypto::{elgamal, group::point_from_compressed, nizk::cds::CDSProof};
use saksi_protocol::{Ballot, ElectionParameters, WIRE_VERSION};

use crate::report::ReportBuilder;

/// Verifies every ballot in `ballots` against `parameters`, the rebuilt joint
/// public key, the issuer key, and the auditor's `binding_context`. Pushes
/// per-ballot findings (one per check, per ballot) onto `builder`. Returns
/// the set of ballots whose CDS proofs *and* credential presentations both
/// passed — only those are eligible to be folded into the homomorphic tally.
pub(crate) fn verify_ballots<'a>(
    parameters: &ElectionParameters,
    ballots: &'a [Ballot],
    election_public_key: &elgamal::PublicKey,
    issuer_public_key: &IssuerPublicKey,
    binding_context: &[u8],
    builder: &mut ReportBuilder,
) -> Vec<&'a Ballot> {
    let binary_choice_set = [Scalar::ZERO, Scalar::ONE];

    let mut eligible = Vec::with_capacity(ballots.len());

    for (idx, ballot) in ballots.iter().enumerate() {
        // The CDS proofs are bound to this ballot's nullifier (order-independent,
        // the same binding the chaincode reconstructs at endorsement — ADR-0007).
        let nullifier_bytes: Vec<u8> = ballot
            .credential_presentation
            .as_ref()
            .and_then(|p| p.nullifier.as_ref())
            .map(|n| n.value.clone())
            .unwrap_or_default();

        // Contests this ballot's position covers (ADR-0007 one-record-per-position;
        // empty position_id = legacy whole-ballot). The ciphertexts/proofs align in
        // order to these global contest indices.
        let contest_idxs =
            crate::contest_indices_for_position(&parameters.contest_ids, &ballot.position_id);

        // -- wire shape ----------------------------------------------------

        if ballot.version != WIRE_VERSION {
            builder.fail(
                "ballot.shape",
                format!(
                    "ballot[{}] version {} != supported {}",
                    idx, ballot.version, WIRE_VERSION
                ),
            );
            continue;
        }
        if contest_idxs.is_empty() {
            builder.fail(
                "ballot.shape",
                format!(
                    "ballot[{idx}] position {:?} matches no contest in the election parameters",
                    ballot.position_id
                ),
            );
            continue;
        }
        if ballot.ciphertexts.len() != contest_idxs.len()
            || ballot.well_formedness_proofs.len() != contest_idxs.len()
        {
            builder.fail(
                "ballot.shape",
                format!(
                    "ballot[{}] (position {:?}) has {} ciphertexts / {} proofs, expected {} (one per position candidate)",
                    idx,
                    ballot.position_id,
                    ballot.ciphertexts.len(),
                    ballot.well_formedness_proofs.len(),
                    contest_idxs.len()
                ),
            );
            continue;
        }
        builder.pass(
            "ballot.shape",
            format!("ballot[{idx}] wire shape matches parameters"),
        );

        // -- per-contest CDS check ----------------------------------------

        let mut all_cds_ok = true;
        for (local_idx, &global_idx) in contest_idxs.iter().enumerate() {
            let contest_id = &parameters.contest_ids[global_idx];
            let wire_ct = &ballot.ciphertexts[local_idx];
            let pad_array: [u8; 32] = match wire_ct.pad.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    builder.fail(
                        "ballot.cds_proof",
                        format!(
                            "ballot[{idx}] contest {contest_id}: ciphertext pad has wrong length"
                        ),
                    );
                    all_cds_ok = false;
                    continue;
                }
            };
            let data_array: [u8; 32] = match wire_ct.data.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    builder.fail(
                        "ballot.cds_proof",
                        format!(
                            "ballot[{idx}] contest {contest_id}: ciphertext data has wrong length"
                        ),
                    );
                    all_cds_ok = false;
                    continue;
                }
            };
            let pad = match point_from_compressed(pad_array) {
                Ok(p) => p,
                Err(_) => {
                    builder.fail(
                        "ballot.cds_proof",
                        format!(
                            "ballot[{idx}] contest {contest_id}: ciphertext pad is not a valid ristretto point"
                        ),
                    );
                    all_cds_ok = false;
                    continue;
                }
            };
            let data = match point_from_compressed(data_array) {
                Ok(p) => p,
                Err(_) => {
                    builder.fail(
                        "ballot.cds_proof",
                        format!(
                            "ballot[{idx}] contest {contest_id}: ciphertext data is not a valid ristretto point"
                        ),
                    );
                    all_cds_ok = false;
                    continue;
                }
            };
            let ciphertext = elgamal::Ciphertext::new(pad, data);

            let cds = match CDSProof::from_wire(&ballot.well_formedness_proofs[local_idx]) {
                Ok(c) => c,
                Err(err) => {
                    builder.fail(
                        "ballot.cds_proof",
                        format!(
                            "ballot[{idx}] contest {contest_id}: CDS proof failed to decode: {err}"
                        ),
                    );
                    all_cds_ok = false;
                    continue;
                }
            };

            let context = saksi_crypto::nizk::cds::binding_context(
                parameters.election_id.as_bytes(),
                contest_id.as_bytes(),
                &nullifier_bytes,
            );
            if let Err(err) = cds.verify(
                election_public_key,
                &ciphertext,
                &binary_choice_set,
                &context,
            ) {
                builder.fail(
                    "ballot.cds_proof",
                    format!("ballot[{idx}] contest {contest_id}: CDS verification failed: {err}"),
                );
                all_cds_ok = false;
                continue;
            }
            builder.pass(
                "ballot.cds_proof",
                format!("ballot[{idx}] contest {contest_id}: CDS OR-proof verifies"),
            );
        }

        // -- credential presentation --------------------------------------

        let presentation = match ballot.credential_presentation.as_ref() {
            Some(p) => p,
            None => {
                builder.fail(
                    "ballot.credential",
                    format!("ballot[{idx}] missing credential_presentation"),
                );
                continue;
            }
        };

        // Issuer-pubkey binding (single-issuer v1 assumption).
        let expected_issuer_bytes = issuer_public_key.as_point().compress().to_bytes();
        if presentation.issuer_public_key.as_slice() != expected_issuer_bytes.as_slice() {
            builder.fail(
                "ballot.issuer_binding",
                format!(
                    "ballot[{idx}] credential_presentation.issuer_public_key does not match the trust-anchor issuer key"
                ),
            );
            // Do not skip the presentation verification below — but mark
            // this ballot ineligible for the tally regardless.
            // (verify_presentation will also fail with the wrong embedded
            // key, which would double up the failure noise; we still call
            // it for the explicit ballot.credential finding.)
        } else {
            builder.pass(
                "ballot.issuer_binding",
                format!("ballot[{idx}] embedded issuer_public_key matches trust anchor"),
            );
        }

        let cred_ok = match verify_presentation(
            presentation,
            issuer_public_key,
            parameters.election_id.as_bytes(),
            // Per-position nullifier (ADR-0007): the record's position_id recomputes
            // H_e = nullifier_h(election_id, position_id). Empty = legacy per-election.
            ballot.position_id.as_bytes(),
            binding_context,
        ) {
            Ok(()) => {
                builder.pass(
                    "ballot.credential",
                    format!("ballot[{idx}] credential presentation verifies"),
                );
                true
            }
            Err(err) => {
                builder.fail(
                    "ballot.credential",
                    format!("ballot[{idx}] credential presentation failed: {err}"),
                );
                false
            }
        };

        if all_cds_ok
            && cred_ok
            && presentation.issuer_public_key.as_slice() == expected_issuer_bytes.as_slice()
        {
            eligible.push(ballot);
        }
    }

    eligible
}

/// Test-visible re-export so [`crate::fixtures`] builds CDS proofs with the
/// exact same context the auditor (and the on-chain chaincode) reconstruct:
/// the canonical `binding_context(election_id, contest_id, nullifier)` from
/// saksi-crypto. See [`saksi_crypto::nizk::cds::binding_context`].
#[cfg(any(test, feature = "demo"))]
pub(crate) fn cds_context_for_test(
    election_id: &[u8],
    contest_id: &[u8],
    nullifier: &[u8],
) -> Vec<u8> {
    saksi_crypto::nizk::cds::binding_context(election_id, contest_id, nullifier)
}
