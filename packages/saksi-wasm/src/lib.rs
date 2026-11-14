//! # saksi-wasm
//!
//! The live election voter's steps for the phone's browser: a thin
//! `wasm-bindgen` binding over [`saksi_live`]. It adds no cryptography of its
//! own; every export calls one `saksi_live` function.
//!
//! **Calling convention.** Every export takes one JS string holding the JSON
//! input of `docs/live/wire-format.md` (section "WebAssembly (phone)") and
//! returns one JS string holding the JSON output. `begin_issuance` and
//! `version` take no input. On failure an export throws a JS `Error` whose
//! `message` is the CLI's error object, `{"error": "<message>"}`; no secret
//! appears in it (a malformed input reports only its category and position,
//! as the CLI does).
//!
//! **Secrets.** Inputs are taken as owned strings and wiped once parsed;
//! outputs are serialised into an exactly-sized buffer that is wiped once it
//! has been copied into a JS string; the voter-state, credential and opening
//! structs wipe their strings on drop. JS strings themselves cannot be wiped;
//! the app drops its references (see the wire-format doc).
//!
//! Only the voter's functions are exported. The issuer's (`issuer_presign`,
//! `issuer_sign`) and anything that rebuilds an issuer session are not.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use saksi_live::{ballot, benaloh, codec, codec::LiveResult, election, issuance};

pub use saksi_live;

/// The binding's own version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// The binding's core: JSON in, JSON out, natively testable.
// ---------------------------------------------------------------------------

/// Parses an input. A serde error can quote the offending value, which may be
/// a secret, so only its category and position are reported (the CLI's
/// rule).
fn parse<T: DeserializeOwned>(input: &str) -> Result<T, String> {
    serde_json::from_str(input).map_err(|e| {
        let what = match e.classify() {
            serde_json::error::Category::Io => "unreadable",
            serde_json::error::Category::Syntax => "not valid JSON",
            serde_json::error::Category::Data => {
                "the wrong shape for this op (a field is missing, unknown or of the wrong type)"
            }
            serde_json::error::Category::Eof => "truncated",
        };
        format!("input is {what} (line {}, column {})", e.line(), e.column())
    })
}

/// Counts the bytes a serialisation needs, so the real one never reallocates
/// (a reallocation would leave a copy of the secret output in freed memory).
struct Counter(usize);

impl std::io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A JSON output whose bytes are wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Output(String);

impl Output {
    /// The JSON text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn serialize<O: Serialize>(value: &O) -> Result<Output, String> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| "output does not serialise")?;
    let mut buf = Vec::with_capacity(counter.0);
    serde_json::to_writer(&mut buf, value).map_err(|_| "output does not serialise")?;
    debug_assert_eq!(buf.len(), buf.capacity());
    String::from_utf8(buf)
        .map(Output)
        .map_err(|_| "output is not UTF-8".into())
}

/// Parses `input`, wipes it, runs `f` and serialises the result.
fn call<I, O>(mut input: String, f: impl FnOnce(&I) -> LiveResult<O>) -> Result<Output, String>
where
    I: DeserializeOwned,
    O: Serialize,
{
    let parsed = parse::<I>(&input);
    input.zeroize();
    let out = f(&parsed?)?;
    serialize(&out)
}

/// `{"error": "<message>"}`, the CLI's error object.
pub fn error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

/// `version()` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    /// `saksi-wasm`.
    pub name: String,
    /// The binding's version.
    pub version: String,
    /// The live wire-format version string ([`saksi_live::WIRE_FORMAT`]).
    pub wire_format: String,
    /// The protobuf wire version (`saksi_protocol::WIRE_VERSION`).
    pub protocol_wire_version: u32,
    /// The saksi commit the build script built from, when it was given one
    /// (`SAKSI_WASM_GIT_REV` at build time).
    pub git_rev: Option<String>,
}

/// The [`version`] value.
pub fn version_info() -> VersionInfo {
    VersionInfo {
        name: env!("CARGO_PKG_NAME").into(),
        version: VERSION.into(),
        wire_format: saksi_live::WIRE_FORMAT.into(),
        protocol_wire_version: saksi_protocol::WIRE_VERSION,
        git_rev: option_env!("SAKSI_WASM_GIT_REV").map(str::to_string),
    }
}

/// `check_credential` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckCredentialRequest {
    /// Hex `ElectionParameters`; the credential is checked against its issuer
    /// key.
    pub params: String,
    /// The stored credential (secret).
    pub credential: issuance::CredentialParts,
}

/// `check_credential` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckCredentialResponse {
    /// Always true: a credential that is not usable is refused with an error.
    pub usable: bool,
    /// The election whose issuer signed it.
    pub election_id: String,
    /// That issuer's key (point hex).
    pub issuer_public_key: String,
    /// The credential's public commitment `C = s_cred·G` (point hex).
    pub commitment: String,
}

/// Rebuilds a stored credential and checks the election's issuer signed it.
pub fn check_credential_core(req: &CheckCredentialRequest) -> LiveResult<CheckCredentialResponse> {
    let params: saksi_protocol::ElectionParameters = codec::message(&req.params, "params")?;
    if params.issuer_public_key.is_empty() {
        return Err("the election parameters carry no issuer key".into());
    }
    let issuer_hex = hex::encode(&params.issuer_public_key);
    let issuer = issuance::issuer_public_key(&issuer_hex)?;
    let credential = issuance::credential(&req.credential, &issuer)?;
    Ok(CheckCredentialResponse {
        usable: true,
        election_id: params.election_id,
        issuer_public_key: issuer_hex,
        commitment: codec::point_hex(&credential.public_commitment()),
    })
}

/// `build_ballot` output: the CLI `ballot` output plus the opening.
#[derive(Clone, Serialize)]
pub struct BuildBallotResponse {
    /// The wire-format `ballot` output.
    #[serde(flatten)]
    pub ballot: ballot::BallotResponse,
    /// Secret: kept in memory only, for `benaloh_open`; dropped once the
    /// ballot is cast.
    pub opening: ballot::BallotOpening,
}

/// One position's ballot, with its Benaloh opening.
pub fn build_ballot_core(req: &ballot::BallotRequest) -> LiveResult<BuildBallotResponse> {
    let (ballot, opening) = ballot::build_ballot_with_opening(req, &mut OsRng)?;
    Ok(BuildBallotResponse { ballot, opening })
}

/// `tracking_code` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackingCodeRequest {
    /// A ballot's nullifier (hex).
    pub nullifier: String,
}

/// `tracking_code` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrackingCodeResponse {
    /// `BC-XXXX-XXXX`.
    pub tracking_code: String,
}

/// The tracking code of a nullifier.
pub fn tracking_code_core(req: &TrackingCodeRequest) -> LiveResult<TrackingCodeResponse> {
    let nullifier = codec::bytes(&req.nullifier, "nullifier")?;
    Ok(TrackingCodeResponse {
        tracking_code: election::tracking_code(&nullifier),
    })
}

/// Every export by name, over its JSON input. `begin_issuance` and `version`
/// ignore the input. Used by the wasm exports and the native tests.
pub fn dispatch(op: &str, input: String) -> Result<Output, String> {
    match op {
        "version" => serialize(&version_info()),
        "begin_issuance" => serialize(&issuance::voter_begin(&mut OsRng)),
        "blind_challenge" => call(input, |r| issuance::voter_blind(r, &mut OsRng)),
        "finalize_issuance" => call(input, issuance::voter_finalize),
        "check_credential" => call(input, check_credential_core),
        "election_info" => call(input, election::election_info),
        "build_ballot" => call(input, build_ballot_core),
        "benaloh_open" => call(input, benaloh::open),
        "benaloh_check" => call(input, benaloh::check),
        "tracking_code" => call(input, tracking_code_core),
        other => Err(format!("unknown op {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// The wasm exports.
// ---------------------------------------------------------------------------

fn export(op: &str, input: String) -> Result<JsValue, JsError> {
    match dispatch(op, input) {
        Ok(out) => Ok(JsValue::from_str(out.as_str())),
        Err(e) => Err(JsError::new(&error_json(&e))),
    }
}

/// `{"name", "version", "wire_format", "protocol_wire_version", "git_rev"}`.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn version() -> Result<JsValue, JsError> {
    export("version", String::new())
}

/// Voter issuance step 1: `{"blinded_commitment", "state"}`. `state` is
/// secret.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn begin_issuance() -> Result<JsValue, JsError> {
    export("begin_issuance", String::new())
}

/// Voter issuance step 2 (`voter-blind`): `{"state", "r",
/// "issuer_public_key"}` -> `{"e_prime", "state"}`.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn blind_challenge(input: String) -> Result<JsValue, JsError> {
    export("blind_challenge", input)
}

/// Voter issuance step 3 (`voter-finalize`): `{"state", "s_iss",
/// "issuer_public_key"}` -> `{"credential", "commitment"}`.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn finalize_issuance(input: String) -> Result<JsValue, JsError> {
    export("finalize_issuance", input)
}

/// `{"params", "credential"}` -> `{"usable": true, "election_id",
/// "issuer_public_key", "commitment"}`; throws for a credential this
/// election's issuer did not sign.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn check_credential(input: String) -> Result<JsValue, JsError> {
    export("check_credential", input)
}

/// `{"params", "dkg"}` -> positions, trustees and the joint key with its
/// fingerprint.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn election_info(input: String) -> Result<JsValue, JsError> {
    export("election_info", input)
}

/// The CLI `ballot` input -> its output plus `opening` (secret).
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn build_ballot(input: String) -> Result<JsValue, JsError> {
    export("build_ballot", input)
}

/// `{"ballot", "opening"}` -> the opened values of a challenged ballot.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn benaloh_open(input: String) -> Result<JsValue, JsError> {
    export("benaloh_open", input)
}

/// `{"params", "dkg", "ballot", "opened"}` -> per-slot verdicts and the
/// candidate the ballot encodes.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn benaloh_check(input: String) -> Result<JsValue, JsError> {
    export("benaloh_check", input)
}

/// `{"nullifier"}` -> `{"tracking_code"}`.
#[wasm_bindgen(unchecked_return_type = "string")]
pub fn tracking_code(input: String) -> Result<JsValue, JsError> {
    export("tracking_code", input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn run(op: &str, input: Value) -> Result<Value, String> {
        dispatch(op, input.to_string()).map(|o| serde_json::from_str(o.as_str()).unwrap())
    }

    #[test]
    fn version_names_the_wire_format() {
        let v = run("version", json!({})).unwrap();
        assert_eq!(v["name"], "saksi-wasm");
        assert_eq!(v["wire_format"], saksi_live::WIRE_FORMAT);
        assert_eq!(v["version"], VERSION);
    }

    #[test]
    fn a_malformed_input_names_no_value() {
        let secret = "ab".repeat(32);
        let input =
            json!({ "state": { "s_cred": secret, "b": secret }, "r": 5, "issuer_public_key": "x" });
        let err = run("blind_challenge", input).unwrap_err();
        assert!(err.starts_with("input is the wrong shape"), "{err}");
        assert!(!err.contains(&secret));
        let err = dispatch("finalize_issuance", format!("{{\"state\": \"{secret}"))
            .err()
            .unwrap();
        assert!(!err.contains(&secret), "{err}");
        assert_eq!(
            serde_json::from_str::<Value>(&error_json(&err)).unwrap()["error"],
            json!(err)
        );
    }

    #[test]
    fn the_output_buffer_is_sized_exactly() {
        let begin = issuance::voter_begin(&mut OsRng);
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, &begin).unwrap();
        let out = serialize(&begin).unwrap();
        assert_eq!(out.0.len(), counter.0);
        assert_eq!(out.0.capacity(), counter.0);
    }

    #[test]
    fn tracking_code_matches_the_board() {
        let v = run(
            "tracking_code",
            json!({ "nullifier": "7f3a92c1".to_string() + &"00".repeat(28) }),
        )
        .unwrap();
        assert_eq!(v["tracking_code"], "BC-7F3A-92C1");
    }

    #[test]
    fn unknown_ops_are_refused() {
        assert!(dispatch("issuer_sign", String::new()).is_err());
    }
}
