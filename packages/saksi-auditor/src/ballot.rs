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
    let contest_count = parameters.contest_ids.len();
    let binary_choice_set = [Scalar::ZERO, Scalar::ONE];

    let mut eligible = Vec::with_capacity(ballots.len());

    for (idx, ballot) in ballots.iter().enumerate() {
        let serial = idx as u64;
        let serial_bytes = serial.to_be_bytes();

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
        if ballot.ciphertexts.len() != contest_count
            || ballot.well_formedness_proofs.len() != contest_count
        {
            builder.fail(
                "ballot.shape",
                format!(
                    "ballot[{}] has {} ciphertexts / {} proofs, expected {} (one per contest)",
                    idx,
                    ballot.ciphertexts.len(),
                    ballot.well_formedness_proofs.len(),
                    contest_count
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
        for (contest_idx, contest_id) in parameters.contest_ids.iter().enumerate() {
            let wire_ct = &ballot.ciphertexts[contest_idx];
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

            let cds = match CDSProof::from_wire(&ballot.well_formedness_proofs[contest_idx]) {
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

            let context = cds_context(binding_context, contest_id.as_bytes(), &serial_bytes);
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

/// Build the per-ballot CDS transcript context — `binding_context ||
/// contest_id || ballot_serial` with explicit length prefixes so the three
/// fields can't be smushed together ambiguously.
fn cds_context(binding_context: &[u8], contest_id: &[u8], serial: &[u8]) -> Vec<u8> {
    let mut ctx =
        Vec::with_capacity(binding_context.len() + contest_id.len() + serial.len() + 3 * 8);
    ctx.extend_from_slice(&(binding_context.len() as u64).to_be_bytes());
    ctx.extend_from_slice(binding_context);
    ctx.extend_from_slice(&(contest_id.len() as u64).to_be_bytes());
    ctx.extend_from_slice(contest_id);
    ctx.extend_from_slice(&(serial.len() as u64).to_be_bytes());
    ctx.extend_from_slice(serial);
    ctx
}

/// Test-visible re-export so [`crate::fixtures`] can build CDS proofs with
/// the exact same context bytes the auditor reconstructs.
#[cfg(test)]
pub(crate) fn cds_context_for_test(
    binding_context: &[u8],
    contest_id: &[u8],
    serial: u64,
) -> Vec<u8> {
    cds_context(binding_context, contest_id, &serial.to_be_bytes())
}
