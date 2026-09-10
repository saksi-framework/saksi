//! DKG transcript verification.
//!
//! Verifies the published [`saksi_protocol::DKGTranscript`] is *shape-consistent*
//! with the election parameters and that every coefficient commitment decodes
//! to a valid ristretto point. Reconstructs the joint election public key
//! `Y = Σ_d A_{d,0}` (sum of the constant-term coefficient commitments) and
//! the per-trustee public share `pub_k = Σ_d Σ_j (k+1)^j · A_{d,j}` used by
//! [`crate::decryption`] to verify each partial-decryption Chaum-Pedersen
//! proof.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};

use saksi_crypto::group::point_from_compressed;
use saksi_protocol::{DKGTranscript, ElectionParameters, WIRE_VERSION};

use crate::report::ReportBuilder;

/// Output of a successful DKG verification.
///
/// `joint_public_key` is the election public key `Y = Σ_d A_{d,0}` (sum of
/// every trustee's constant-term coefficient commitment); `trustee_share_publics`
/// is the per-trustee aggregated public share `pub_k = Σ_d eval(A_d, k+1)`,
/// indexed in the order of `parameters.trustee_ids`.
#[derive(Clone, Debug)]
pub(crate) struct DkgVerification {
    pub(crate) joint_public_key: RistrettoPoint,
    pub(crate) trustee_share_publics: Vec<RistrettoPoint>,
}

/// Run all DKG-transcript checks. Returns `Some(DkgVerification)` if the
/// transcript decoded cleanly enough for downstream checks (joint pubkey and
/// share publics rebuilt); returns `None` if a shape or decode error means we
/// cannot meaningfully audit ballots / partial decryptions. Either way the
/// findings are pushed onto `builder`.
pub(crate) fn verify_dkg_transcript(
    parameters: &ElectionParameters,
    transcript: &DKGTranscript,
    builder: &mut ReportBuilder,
) -> Option<DkgVerification> {
    // -- shape --------------------------------------------------------------

    if transcript.version != WIRE_VERSION {
        builder.fail(
            "dkg.shape",
            format!(
                "DKG transcript version {} != supported {}",
                transcript.version, WIRE_VERSION
            ),
        );
        return None;
    }

    if transcript.threshold != parameters.threshold {
        builder.fail(
            "dkg.shape",
            format!(
                "DKG transcript threshold {} != parameters threshold {}",
                transcript.threshold, parameters.threshold
            ),
        );
        return None;
    }

    if transcript.trustee_commitments.len() != parameters.trustee_ids.len() {
        builder.fail(
            "dkg.shape",
            format!(
                "DKG transcript has {} trustee commitments, expected {}",
                transcript.trustee_commitments.len(),
                parameters.trustee_ids.len()
            ),
        );
        return None;
    }

    let threshold = parameters.threshold as usize;
    for commit in &transcript.trustee_commitments {
        if commit.coefficient_commitments.len() != threshold {
            builder.fail(
                "dkg.shape",
                format!(
                    "trustee {} has {} coefficient commitments, expected threshold {}",
                    commit.trustee_id,
                    commit.coefficient_commitments.len(),
                    threshold
                ),
            );
            return None;
        }
    }
    builder.pass("dkg.shape", "DKG transcript shape matches parameters");

    // -- decode every commitment -------------------------------------------

    let decoded = match decode_trustee_commitments(transcript) {
        Ok(decoded) => decoded,
        Err(detail) => {
            builder.fail("dkg.decode", detail);
            return None;
        }
    };
    builder.pass(
        "dkg.decode",
        "every DKG coefficient commitment decoded to a valid ristretto point",
    );

    // -- joint public key Y = Σ_d A_{d,0} ----------------------------------

    let mut joint_public_key = RistrettoPoint::identity();
    for points in &decoded {
        // shape check above guarantees `points` has `threshold` entries and
        // `threshold >= 1` (parameters check enforces threshold <= trustees,
        // and `trustees >= 1`).
        joint_public_key += points[0];
    }
    builder.pass(
        "dkg.joint_public_key",
        "joint election public key rebuilt from trustee constant terms",
    );

    // -- per-trustee public share pub_k = Σ_d Σ_j (k+1)^j · A_{d,j} --------

    let trustee_count = parameters.trustee_ids.len();
    let trustee_share_publics = (1..=trustee_count as u64)
        .map(|index| trustee_verification_key(&decoded, index))
        .collect();
    builder.pass(
        "dkg.trustee_share_publics",
        "per-trustee aggregated public shares evaluated from coefficient commitments",
    );

    Some(DkgVerification {
        joint_public_key,
        trustee_share_publics,
    })
}

/// Decodes every trustee's `coefficient_commitments` into ristretto points, in
/// transcript order. `Err` carries the human-readable reason (reported as a
/// `dkg.decode` finding).
pub(crate) fn decode_trustee_commitments(
    transcript: &DKGTranscript,
) -> Result<Vec<Vec<RistrettoPoint>>, String> {
    transcript
        .trustee_commitments
        .iter()
        .map(|commit| {
            commit
                .coefficient_commitments
                .iter()
                .enumerate()
                .map(|(j, bytes)| {
                    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        format!(
                            "trustee {} coefficient_commitments[{}] has wrong length: {}",
                            commit.trustee_id,
                            j,
                            bytes.len()
                        )
                    })?;
                    point_from_compressed(array).map_err(|_| {
                        format!(
                            "trustee {} coefficient_commitments[{}] is not a valid ristretto point",
                            commit.trustee_id, j
                        )
                    })
                })
                .collect()
        })
        .collect()
}

/// Public verification key of the trustee holding DKG share index `index`:
///
/// ```text
/// vk_i = Σ_j Σ_k C_{j,k} · i^k
/// ```
///
/// summed over **every** dealer `j` in the transcript and each of that dealer's
/// coefficient commitments `C_{j,k} = a_{j,k}·G`. Because the DKG hands trustee
/// `i` the share `s_i = Σ_j f_j(i)`, this is exactly `s_i·G` — the key that
/// verifies that trustee's Chaum-Pedersen partial-decryption proofs and its
/// Schnorr signature over the published tally.
///
/// **Index convention: 1-based, in transcript/parameters order.**
/// `saksi_crypto::dkg::run_in_memory` gives the k-th trustee (0-based `k`) the
/// share `Σ_j f_j(k + 1)` — it evaluates every dealer polynomial at
/// `recipient_id = k + 1` — so the k-th entry of `parameters.trustee_ids`
/// evaluates at `x = k + 1`, never at `x = 0` (which would yield the joint
/// public key rather than a share's public). The Go chaincode copies this
/// convention verbatim; the golden vector
/// `saksi-protocol/test-vectors/tally-sig-v1.hex` pins the resulting keys.
pub(crate) fn trustee_verification_key(
    commitments: &[Vec<RistrettoPoint>],
    index: u64,
) -> RistrettoPoint {
    let x = Scalar::from(index);
    let mut sum = RistrettoPoint::identity();
    for points in commitments {
        // Horner: A_0 + x·(A_1 + x·(A_2 + ...))
        let mut acc = RistrettoPoint::identity();
        for coeff in points.iter().rev() {
            acc = acc * x + coeff;
        }
        sum += acc;
    }
    sum
}
