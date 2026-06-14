//! Demo election generator + bundle (de)serialization (`demo` feature).
//!
//! Builds the same happy-path election the auditor's own tests use and
//! serializes its wire artifacts into a flat JSON **bundle** of hex strings, so
//! an external driver (the Go `saksi-console`) can submit them to a live
//! bulletin board and the auditor can re-verify the published set.
//!
//! Bundle layout:
//!
//! ```json
//! {
//!   "election_id": "election-2026",
//!   "params": "<hex ElectionParameters>",
//!   "dkg": "<hex DKGTranscript>",
//!   "issuer_pk": "<hex compressed ristretto point>",
//!   "binding_context": "<hex>",
//!   "ballots": ["<hex Ballot>", ...],
//!   "partial_decryptions": ["<hex PartialDecryption>", ...],
//!   "tally": "<hex TallyResult>"
//! }
//! ```

use prost::Message;

use saksi_credentials::IssuerPublicKey;
use saksi_crypto::group::{compress_point, point_from_compressed};
use saksi_protocol::{Ballot, DKGTranscript, ElectionParameters, PartialDecryption, TallyResult};

use crate::fixtures::happy_path_fixture;
use crate::{audit, AuditReport, ElectionArtifacts};

/// Builds the canonical happy-path election (5 trustees / threshold 3, 2
/// contests, 6 voters) and returns it as a pretty-printed JSON bundle of
/// hex-encoded wire messages.
pub fn election_bundle_json() -> String {
    let f = happy_path_fixture();
    let art = f.artifacts();

    let ballots: Vec<String> = art
        .ballots
        .iter()
        .map(|b| hex::encode(b.encode_to_vec()))
        .collect();
    let partials: Vec<String> = art
        .partial_decryptions
        .iter()
        .map(|p| hex::encode(p.encode_to_vec()))
        .collect();

    let value = serde_json::json!({
        "election_id": art.parameters.election_id,
        "params": hex::encode(art.parameters.encode_to_vec()),
        "dkg": hex::encode(art.dkg_transcript.encode_to_vec()),
        "issuer_pk": hex::encode(compress_point(art.issuer_public_key.as_point())),
        "binding_context": hex::encode(art.binding_context),
        "ballots": ballots,
        "partial_decryptions": partials,
        "tally": hex::encode(art.tally.encode_to_vec()),
    });
    serde_json::to_string_pretty(&value).expect("bundle serializes")
}

/// Parses a bundle produced by [`election_bundle_json`] (or read back from the
/// chain in the same shape) and runs the full audit over it.
pub fn audit_bundle_json(bundle: &str) -> Result<AuditReport, String> {
    let v: serde_json::Value =
        serde_json::from_str(bundle).map_err(|e| format!("parse bundle: {e}"))?;

    let field_bytes = |key: &str| -> Result<Vec<u8>, String> {
        let h = v[key]
            .as_str()
            .ok_or_else(|| format!("bundle missing string field {key:?}"))?;
        hex::decode(h).map_err(|e| format!("field {key:?} is not valid hex: {e}"))
    };
    let array_bytes = |key: &str| -> Result<Vec<Vec<u8>>, String> {
        v[key]
            .as_array()
            .ok_or_else(|| format!("bundle field {key:?} is not an array"))?
            .iter()
            .map(|item| {
                let h = item
                    .as_str()
                    .ok_or_else(|| format!("a {key:?} entry is not a string"))?;
                hex::decode(h).map_err(|e| format!("a {key:?} entry is not valid hex: {e}"))
            })
            .collect()
    };

    let parameters = ElectionParameters::decode(&field_bytes("params")?[..])
        .map_err(|e| format!("decode params: {e}"))?;
    let dkg_transcript =
        DKGTranscript::decode(&field_bytes("dkg")?[..]).map_err(|e| format!("decode dkg: {e}"))?;
    let tally = TallyResult::decode(&field_bytes("tally")?[..])
        .map_err(|e| format!("decode tally: {e}"))?;

    let issuer_pk_bytes: [u8; 32] = field_bytes("issuer_pk")?
        .try_into()
        .map_err(|_| "issuer_pk is not 32 bytes".to_string())?;
    let issuer_point = point_from_compressed(issuer_pk_bytes)
        .map_err(|_| "issuer_pk is not a valid point".to_string())?;
    let issuer_public_key = IssuerPublicKey(issuer_point);

    let binding_context = field_bytes("binding_context")?;

    let ballots: Vec<Ballot> = array_bytes("ballots")?
        .iter()
        .map(|b| Ballot::decode(&b[..]).map_err(|e| format!("decode ballot: {e}")))
        .collect::<Result<_, String>>()?;
    let partial_decryptions: Vec<PartialDecryption> = array_bytes("partial_decryptions")?
        .iter()
        .map(|p| PartialDecryption::decode(&p[..]).map_err(|e| format!("decode partial: {e}")))
        .collect::<Result<_, String>>()?;

    let artifacts = ElectionArtifacts {
        parameters: &parameters,
        dkg_transcript: &dkg_transcript,
        ballots: &ballots,
        partial_decryptions: &partial_decryptions,
        tally: &tally,
        binding_context: &binding_context,
        issuer_public_key: &issuer_public_key,
    };
    Ok(audit(artifacts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditStatus;

    #[test]
    fn generated_bundle_audits_clean() {
        let bundle = election_bundle_json();
        let report = audit_bundle_json(&bundle).expect("bundle audits");
        assert_eq!(
            report.overall,
            AuditStatus::Pass,
            "round-tripped demo bundle must audit clean: {report:#?}"
        );
    }
}
