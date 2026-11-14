//! `saksi-demo live <op>`: the live election's crypto steps as one-shot
//! processes.
//!
//! Each op reads one JSON object on stdin and writes one JSON object on
//! stdout. On failure it exits non-zero and writes `{"error": "..."}` on
//! stderr. Each op receives only the secrets of the party that runs it: key,
//! session and share files are named by path, are written with mode 0600, and
//! are refused when another user could read them. No secret is ever written to
//! stderr. The wire format is `docs/live/wire-format.md`.
//!
//! The crypto is the library's: `saksi_live` for the voter's and the dealer's
//! steps, `saksi_auditor::live` for every check the auditor already makes,
//! and `saksi_ffi_tauri::commands::partial_decrypt_v2` for partial decryption.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize;

use saksi_auditor::live::{cp_context, verify_live, verify_live_dir, LiveElection, LiveRecord};
use saksi_crypto::{
    dkg::{DealerCommitments, DkgOutput},
    elgamal::{Ciphertext, PublicKey},
    group::basepoint,
    nizk::{chaum_pedersen::ChaumPedersenProof, schnorr::SchnorrProof},
};
use saksi_live::{ballot, codec, dkg, election, issuance};
use saksi_protocol::{PartialDecryption, TallyResult, TrusteeSignature, WIRE_VERSION};

type R<T> = Result<T, String>;

/// Every op, for the usage line and the wire-format doc test.
pub const OPS: &[&str] = &[
    "election-params",
    "issuer-keygen",
    "issue-presign",
    "issue-sign",
    "trustee-keygen",
    "dkg-deal",
    "dkg-receive",
    "dkg-transcript",
    "aggregate",
    "partial",
    "combine",
    "sign-tally",
    "tally-assemble",
    "voter-begin",
    "voter-blind",
    "voter-finalize",
    "ballot",
    "verify-live",
];

pub fn cli(args: &[String]) -> ExitCode {
    let Some(op) = args.first().map(String::as_str) else {
        return fail(&format!(
            "usage: saksi-demo live <{}> < input.json",
            OPS.join("|")
        ));
    };
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        return fail(&format!("read stdin: {e}"));
    }
    let result = dispatch(op, &input);
    input.zeroize();
    match result {
        Ok(out) => {
            let mut stdout = std::io::stdout().lock();
            if writeln!(stdout, "{out}")
                .and_then(|_| stdout.flush())
                .is_err()
            {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("{}", json!({ "error": message }));
    ExitCode::FAILURE
}

fn dispatch(op: &str, input: &str) -> R<Value> {
    match op {
        "election-params" => to_value(election::election_params(&parse(input)?)?),
        "issuer-keygen" => issuer_keygen(parse(input)?),
        "issue-presign" => issue_presign(parse(input)?),
        "issue-sign" => issue_sign(parse(input)?),
        "trustee-keygen" => trustee_keygen(parse(input)?),
        "dkg-deal" => dkg_deal(parse(input)?),
        "dkg-receive" => dkg_receive(parse(input)?),
        "dkg-transcript" => dkg_transcript(parse(input)?),
        "aggregate" => aggregate(parse(input)?),
        "partial" => partial(parse(input)?),
        "combine" => combine(parse(input)?),
        "sign-tally" => sign_tally(parse(input)?),
        "tally-assemble" => tally_assemble(parse(input)?),
        "voter-begin" => {
            let _: Empty = parse(input)?;
            to_value(issuance::voter_begin(&mut OsRng))
        }
        "voter-blind" => to_value(issuance::voter_blind(&parse(input)?, &mut OsRng)?),
        "voter-finalize" => to_value(issuance::voter_finalize(&parse(input)?)?),
        "ballot" => to_value(ballot::build_ballot(&parse(input)?, &mut OsRng)?),
        "verify-live" => verify(parse(input)?),
        other => Err(format!(
            "unknown live op {other:?}; ops: {}",
            OPS.join(", ")
        )),
    }
}

/// Parses stdin. A serde error can quote the offending value, which may be a
/// secret, so only its category and position are reported.
fn parse<T: DeserializeOwned>(input: &str) -> R<T> {
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

fn to_value<T: Serialize>(v: T) -> R<Value> {
    serde_json::to_value(v).map_err(|e| format!("serialize output: {e}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

// ---------------------------------------------------------------------------
// Secret files
// ---------------------------------------------------------------------------

/// Creates `path` with mode 0600 and writes `value`. Never overwrites.
fn write_secret(path: &str, value: &Value) -> R<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{path} already exists; refusing to overwrite a secret file")
        } else {
            format!("create {path}: {e}")
        }
    })?;
    let mut body = value.to_string();
    let written = file
        .write_all(body.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write {path}: {e}"));
    body.zeroize();
    written
}

/// Reads a secret file of `kind`. Refuses one another user could read.
fn read_secret<T: DeserializeOwned>(path: &str, kind: &str) -> R<T> {
    let meta = fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{path} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{path} is readable by other users (mode {:o}); want 0600",
                meta.permissions().mode() & 0o777
            ));
        }
    }
    let mut raw = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let parsed: R<Value> = serde_json::from_str(&raw).map_err(|_| format!("{path} is not JSON"));
    raw.zeroize();
    let parsed = parsed?;
    if parsed.get("kind").and_then(Value::as_str) != Some(kind) {
        return Err(format!("{path} is not a {kind} file"));
    }
    serde_json::from_value(parsed).map_err(|_| format!("{path} is a malformed {kind} file"))
}

const ISSUER_KEY: &str = "saksi-live-issuer-key-v1";
const RECEIVE_KEY: &str = "saksi-live-trustee-receive-key-v1";
const SESSION: &str = "saksi-live-issuer-session-v1";
const SHARE: &str = "saksi-live-trustee-share-v1";

#[derive(Deserialize)]
struct IssuerKeyFile {
    #[allow(dead_code)]
    kind: String,
    secret: String,
    public_key: String,
}

#[derive(Deserialize)]
struct ReceiveKeyFile {
    #[allow(dead_code)]
    kind: String,
    trustee_id: usize,
    secret: String,
    public_key: String,
}

#[derive(Deserialize)]
struct SessionFile {
    #[allow(dead_code)]
    kind: String,
    k: String,
}

#[derive(Deserialize, Serialize)]
struct ShareFile {
    kind: String,
    election_id: String,
    trustee_id: usize,
    threshold: usize,
    trustees: usize,
    share: String,
    verification_key: String,
    joint_public_key: String,
    fingerprint: String,
}

/// A secret scalar that matches its recorded public point.
fn keypair(secret: &str, public: &str, path: &str) -> R<Scalar> {
    let s = codec::scalar(secret, path)?;
    if codec::point(public, path)? != s * basepoint() {
        return Err(format!("{path}: secret and public key do not match"));
    }
    Ok(s)
}

fn issuer_secret(path: &str) -> R<Scalar> {
    let f: IssuerKeyFile = read_secret(path, ISSUER_KEY)?;
    keypair(&f.secret, &f.public_key, path)
}

/// A secret string that is wiped when it goes out of scope.
struct Wiped(String);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.as_mut_str().zeroize();
    }
}

struct Share {
    election_id: String,
    trustee_id: usize,
    value: Scalar,
}

impl Drop for Share {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

fn read_share(path: &str) -> R<Share> {
    let f: ShareFile = read_secret(path, SHARE)?;
    Ok(Share {
        election_id: f.election_id,
        trustee_id: f.trustee_id,
        value: keypair(&f.share, &f.verification_key, path)?,
    })
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeygenIn {
    key_file: String,
}

fn issuer_keygen(i: KeygenIn) -> R<Value> {
    let (mut secret, public) = issuance::issuer_keygen(&mut OsRng);
    let public_key = codec::point_hex(public.as_point());
    let written = write_secret(
        &i.key_file,
        &json!({ "kind": ISSUER_KEY, "secret": codec::scalar_hex(&secret), "public_key": public_key }),
    );
    secret.zeroize();
    written?;
    Ok(json!({ "public_key": public_key }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PresignIn {
    issuer_key_file: String,
    blinded_commitment: String,
    session_file: String,
}

fn issue_presign(i: PresignIn) -> R<Value> {
    let mut sk = issuer_secret(&i.issuer_key_file)?;
    let result = issuance::issuer_presign(&sk, &i.blinded_commitment, &mut OsRng);
    sk.zeroize();
    let (r, mut k) = result?;
    let written = write_secret(
        &i.session_file,
        &json!({ "kind": SESSION, "k": codec::scalar_hex(&k) }),
    );
    k.zeroize();
    written?;
    Ok(json!({ "r": r }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignIn {
    issuer_key_file: String,
    session_file: String,
    e_prime: String,
}

fn issue_sign(i: SignIn) -> R<Value> {
    let mut sk = issuer_secret(&i.issuer_key_file)?;
    let session: SessionFile = read_secret(&i.session_file, SESSION)?;
    // Destroy the session before using it: a nonce signs one challenge only.
    // Two responses under one nonce would reveal the issuer key.
    fs::remove_file(&i.session_file).map_err(|e| {
        format!(
            "cannot consume session {}: {e}; not signing",
            i.session_file
        )
    })?;
    let k = codec::scalar(&session.k, "session")?;
    let result = issuance::issuer_sign(&sk, k, &i.e_prime);
    sk.zeroize();
    Ok(json!({ "s_iss": result? }))
}

// ---------------------------------------------------------------------------
// Trustee DKG
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrusteeKeygenIn {
    trustee_id: usize,
    key_file: String,
}

fn trustee_keygen(i: TrusteeKeygenIn) -> R<Value> {
    if i.trustee_id == 0 {
        return Err("trustee_id starts at 1".into());
    }
    let (mut secret, public) = dkg::receive_keygen(&mut OsRng);
    let public_key = codec::point_hex(&public);
    let written = write_secret(
        &i.key_file,
        &json!({ "kind": RECEIVE_KEY, "trustee_id": i.trustee_id,
                 "secret": codec::scalar_hex(&secret), "public_key": public_key }),
    );
    secret.zeroize();
    written?;
    Ok(json!({ "trustee_id": i.trustee_id, "receive_public_key": public_key }))
}

fn receive_secret(path: &str, trustee_id: usize) -> R<Scalar> {
    let f: ReceiveKeyFile = read_secret(path, RECEIVE_KEY)?;
    if f.trustee_id != trustee_id {
        return Err(format!(
            "{path} is trustee {}'s key, not trustee {trustee_id}'s",
            f.trustee_id
        ));
    }
    keypair(&f.secret, &f.public_key, path)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DealIn {
    receive_key_file: String,
    election_id: String,
    dealer_id: usize,
    threshold: usize,
    trustees: usize,
    peers: Vec<dkg::Peer>,
}

fn dkg_deal(i: DealIn) -> R<Value> {
    let mut secret = receive_secret(&i.receive_key_file, i.dealer_id)?;
    let out = dkg::deal(
        &dkg::DealRequest {
            election_id: i.election_id,
            dealer_id: i.dealer_id,
            threshold: i.threshold,
            trustees: i.trustees,
            peers: i.peers,
        },
        &secret,
        &mut OsRng,
    );
    secret.zeroize();
    to_value(out?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveIn {
    receive_key_file: String,
    share_file: String,
    election_id: String,
    trustee_id: usize,
    threshold: usize,
    trustees: usize,
    dealers: Vec<dkg::DealerInput>,
}

fn dkg_receive(i: ReceiveIn) -> R<Value> {
    let mut secret = receive_secret(&i.receive_key_file, i.trustee_id)?;
    let received = dkg::receive(
        &dkg::ReceiveRequest {
            election_id: i.election_id.clone(),
            trustee_id: i.trustee_id,
            threshold: i.threshold,
            trustees: i.trustees,
            dealers: i.dealers,
        },
        &secret,
    );
    secret.zeroize();
    let received = received?;
    let vk = codec::point_hex(&received.verification_key);
    let joint = codec::point_hex(&received.joint_public_key);
    let fingerprint = dkg::fingerprint(&received.verification_key);
    let mut share_hex = codec::scalar_hex(&received.share);
    let written = write_secret(
        &i.share_file,
        &serde_json::to_value(ShareFile {
            kind: SHARE.into(),
            election_id: i.election_id.clone(),
            trustee_id: i.trustee_id,
            threshold: i.threshold,
            trustees: i.trustees,
            share: share_hex.clone(),
            verification_key: vk.clone(),
            joint_public_key: joint.clone(),
            fingerprint: fingerprint.clone(),
        })
        .map_err(|e| e.to_string())?,
    );
    share_hex.zeroize();
    written?;
    Ok(json!({
        "election_id": i.election_id,
        "trustee_id": i.trustee_id,
        "verification_key": vk,
        "fingerprint": fingerprint,
        "joint_public_key": joint,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptDealer {
    dealer_id: usize,
    commitments: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptIn {
    params: String,
    dealers: Vec<TranscriptDealer>,
}

fn verification_keys(e: &LiveElection) -> Vec<Value> {
    e.parameters
        .trustee_ids
        .iter()
        .zip(&e.verification_keys)
        .map(|(id, vk)| {
            json!({ "trustee_id": id, "verification_key": codec::point_hex(vk),
                    "fingerprint": dkg::fingerprint(vk) })
        })
        .collect()
}

fn dkg_transcript(i: TranscriptIn) -> R<Value> {
    let params: saksi_protocol::ElectionParameters = codec::message(&i.params, "params")?;
    let n = params.trustee_ids.len();
    let mut dealers = i.dealers;
    dealers.sort_by_key(|d| d.dealer_id);
    if dealers.iter().map(|d| d.dealer_id).ne(1..=n) {
        return Err(format!("dealers must be exactly 1..={n}, once each"));
    }
    let commitments = dealers
        .iter()
        .map(|d| {
            Ok(DealerCommitments {
                trustee_id: d.dealer_id,
                coefficient_commitments: d
                    .commitments
                    .iter()
                    .map(|c| codec::point(c, &format!("dealer {} commitment", d.dealer_id)))
                    .collect::<R<Vec<RistrettoPoint>>>()?,
            })
        })
        .collect::<R<Vec<_>>>()?;
    // The library's transcript encoding, over commitments only: no shares
    // reach the console.
    let joint = commitments
        .iter()
        .map(|c| {
            c.coefficient_commitments
                .first()
                .copied()
                .unwrap_or_default()
        })
        .sum();
    let transcript = DkgOutput {
        public_key: PublicKey::from_point(joint),
        trustee_shares: Vec::new(),
        commitments,
        complaints: Vec::new(),
        threshold: params.threshold as usize,
    }
    .to_protocol_transcript(params.election_id.clone());
    // Then the auditor's own transcript checks over the result.
    let e = LiveElection::from_messages(params, transcript.clone())?;
    Ok(json!({
        "dkg": codec::message_hex(&transcript),
        "election_id": e.parameters.election_id,
        "joint_public_key": codec::point_hex(&e.joint_public_key),
        "verification_keys": verification_keys(&e),
    }))
}

// ---------------------------------------------------------------------------
// Tally
// ---------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateContest {
    contest_id: String,
    pad: String,
    data: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Aggregate {
    election_id: String,
    ballot_count: u64,
    contests: Vec<AggregateContest>,
}

impl Aggregate {
    /// The aggregate as ciphertexts, checked against the election's contests.
    fn ciphertexts(&self, e: &LiveElection) -> R<Vec<Ciphertext>> {
        if self.election_id != e.parameters.election_id {
            return Err(format!("aggregate is for election {:?}", self.election_id));
        }
        if self.contests.len() != e.parameters.contest_ids.len()
            || self
                .contests
                .iter()
                .zip(&e.parameters.contest_ids)
                .any(|(c, id)| &c.contest_id != id)
        {
            return Err("aggregate contests are not the election's, in order".into());
        }
        self.contests
            .iter()
            .map(|c| {
                Ok(Ciphertext::new(
                    codec::point(&c.pad, &format!("aggregate {} pad", c.contest_id))?,
                    codec::point(&c.data, &format!("aggregate {} data", c.contest_id))?,
                ))
            })
            .collect()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateIn {
    params: String,
    dkg: String,
    ballots: Vec<String>,
}

fn aggregate(i: AggregateIn) -> R<Value> {
    let e = LiveElection::load(&i.params, &i.dkg)?;
    let cts = e.verify_and_aggregate(&i.ballots)?;
    to_value(Aggregate {
        election_id: e.parameters.election_id.clone(),
        ballot_count: i.ballots.len() as u64,
        contests: e
            .parameters
            .contest_ids
            .iter()
            .zip(&cts)
            .map(|(id, ct)| AggregateContest {
                contest_id: id.clone(),
                pad: codec::point_hex(&ct.pad),
                data: codec::point_hex(&ct.data),
            })
            .collect(),
    })
}

/// The share file's trustee, checked against the election and its transcript.
fn trustee_of(e: &LiveElection, share: &Share) -> R<(String, RistrettoPoint)> {
    if share.election_id != e.parameters.election_id {
        return Err(format!(
            "the share file is for election {:?}",
            share.election_id
        ));
    }
    let id = share.trustee_id.to_string();
    let index = e.trustee_index(&id)?;
    let vk = e.verification_keys[index];
    if share.value * basepoint() != vk {
        return Err(format!(
            "trustee {id}'s share does not match its verification key in the published DKG transcript"
        ));
    }
    Ok((id, vk))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialIn {
    share_file: String,
    params: String,
    dkg: String,
    aggregate: Aggregate,
}

fn partial(i: PartialIn) -> R<Value> {
    let e = LiveElection::load(&i.params, &i.dkg)?;
    let cts = i.aggregate.ciphertexts(&e)?;
    let share = read_share(&i.share_file)?;
    let (trustee_id, vk) = trustee_of(&e, &share)?;
    // Wiped on every return path, including the early ones.
    let secret_hex = Wiped(codec::scalar_hex(&share.value));
    let mut partials = Vec::with_capacity(cts.len());
    let mut produced = Vec::with_capacity(cts.len());
    for (contest_id, ct) in e.parameters.contest_ids.iter().zip(&cts) {
        // The auditor's context bytes; `partial_decrypt_v2` takes them as a
        // string. Ids are ASCII and at most 64 bytes, so every length prefix
        // is one ASCII byte and the conversion is lossless.
        let context = String::from_utf8(cp_context(&trustee_id, contest_id))
            .map_err(|_| format!("contest {contest_id}: context is not UTF-8"))?;
        let dto = saksi_ffi_tauri::commands::partial_decrypt_v2(
            trustee_id.clone(),
            contest_id.clone(),
            secret_hex.0.clone(),
            codec::point_hex(&vk),
            saksi_ffi_tauri::commands::CiphertextDto {
                pad: codec::point_hex(&ct.pad),
                data: codec::point_hex(&ct.data),
            },
            context,
        );
        let dto = match dto {
            Ok(d) => d,
            Err(_) => return Err(format!("contest {contest_id}: partial decryption failed")),
        };
        let proof: saksi_protocol::ChaumPedersenProof =
            codec::message(&dto.proof_bytes_hex, "partial proof")?;
        let pd = PartialDecryption {
            version: WIRE_VERSION,
            trustee_id: trustee_id.clone(),
            share: codec::bytes(&dto.share_hex, "partial share")?,
            proof: Some(proof),
            contest_id: contest_id.clone(),
        };
        partials.push(json!({ "contest_id": contest_id, "partial": codec::message_hex(&pd) }));
        produced.push(pd);
    }
    drop(secret_hex);
    // Self-check: every proof verifies exactly as the auditor will check it.
    for (pd, ct) in produced.iter().zip(&cts) {
        let proof = ChaumPedersenProof::from_wire(pd.proof.as_ref().expect("set above"))
            .map_err(|e| e.to_string())?;
        let point = codec::point(&hex::encode(&pd.share), "share")?;
        proof
            .verify(
                &basepoint(),
                &ct.pad,
                &vk,
                &point,
                &cp_context(&trustee_id, &pd.contest_id),
            )
            .map_err(|_| format!("contest {}: own partial does not verify", pd.contest_id))?;
    }
    Ok(
        json!({ "election_id": e.parameters.election_id, "trustee_id": trustee_id, "partials": partials }),
    )
}

fn decode_partials(partials: &[String]) -> R<Vec<PartialDecryption>> {
    partials
        .iter()
        .enumerate()
        .map(|(n, p)| codec::message(p, &format!("partials[{n}]")))
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CombineIn {
    params: String,
    dkg: String,
    aggregate: Aggregate,
    partials: Vec<String>,
}

fn totals_of(
    e: &LiveElection,
    aggregate: &Aggregate,
    partials: &[PartialDecryption],
) -> R<Vec<u64>> {
    let cts = aggregate.ciphertexts(e)?;
    e.decrypt_totals(&cts, partials, aggregate.ballot_count)
}

fn combine(i: CombineIn) -> R<Value> {
    let e = LiveElection::load(&i.params, &i.dkg)?;
    let totals = totals_of(&e, &i.aggregate, &decode_partials(&i.partials)?)?;
    let contests: Vec<Value> = e
        .parameters
        .contest_ids
        .iter()
        .zip(&totals)
        .map(|(id, t)| json!({ "contest_id": id, "total": t }))
        .collect();
    Ok(json!({ "election_id": e.parameters.election_id, "totals": totals, "contests": contests }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignIn2 {
    share_file: String,
    params: String,
    dkg: String,
    aggregate: Aggregate,
    partials: Vec<String>,
    totals: Vec<u64>,
}

fn sign_tally(i: SignIn2) -> R<Value> {
    let e = LiveElection::load(&i.params, &i.dkg)?;
    // A trustee signs only totals it recomputed itself from the partials.
    let totals = totals_of(&e, &i.aggregate, &decode_partials(&i.partials)?)?;
    if totals != i.totals {
        return Err(format!(
            "the totals to sign {:?} differ from the totals the partials decrypt to {totals:?}",
            i.totals
        ));
    }
    let share = read_share(&i.share_file)?;
    let (trustee_id, vk) = trustee_of(&e, &share)?;
    let context = e.tally_sig_context(&totals);
    let proof = SchnorrProof::prove(&basepoint(), &vk, &share.value, &context, &mut OsRng);
    Ok(json!({
        "election_id": e.parameters.election_id,
        "trustee_id": trustee_id,
        "totals": totals,
        "signature": hex::encode(proof.to_bytes()),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureIn {
    trustee_id: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssembleIn {
    params: String,
    dkg: String,
    aggregate: Aggregate,
    partials: Vec<String>,
    totals: Vec<u64>,
    signatures: Vec<SignatureIn>,
}

fn tally_assemble(i: AssembleIn) -> R<Value> {
    let e = LiveElection::load(&i.params, &i.dkg)?;
    let partials = decode_partials(&i.partials)?;
    let totals = totals_of(&e, &i.aggregate, &partials)?;
    if totals != i.totals {
        return Err(format!(
            "totals {:?} differ from the decrypted {totals:?}",
            i.totals
        ));
    }
    let context = e.tally_sig_context(&totals);
    let mut seen = std::collections::HashSet::new();
    let mut signatures = Vec::with_capacity(i.signatures.len());
    for s in &i.signatures {
        let index = e.trustee_index(&s.trustee_id)?;
        if !seen.insert(index) {
            return Err(format!("trustee {} signed twice", s.trustee_id));
        }
        let raw = codec::bytes(&s.signature, "signature")?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| format!("trustee {}: signature is not 64 bytes", s.trustee_id))?;
        SchnorrProof::from_bytes(&bytes)
            .and_then(|p| p.verify(&basepoint(), &e.verification_keys[index], &context))
            .map_err(|_| {
                format!(
                    "trustee {}: signature does not verify over these totals",
                    s.trustee_id
                )
            })?;
        signatures.push(TrusteeSignature {
            trustee_id: s.trustee_id.clone(),
            signature: raw,
        });
    }
    let threshold = e.parameters.threshold as usize;
    let tally = TallyResult {
        version: WIRE_VERSION,
        election_id: e.parameters.election_id.clone(),
        totals: totals.clone(),
        partial_decryptions: partials,
        signatures,
    };
    Ok(json!({
        "tally": codec::message_hex(&tally),
        "election_id": e.parameters.election_id,
        "totals": totals,
        "signatures": i.signatures.len(),
        "threshold": threshold,
        // Deliberately not enforced here: the console may assemble a tally
        // below threshold to show the chaincode refusing it.
        "meets_threshold": i.signatures.len() >= threshold,
    }))
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyIn {
    #[serde(default)]
    record: Option<LiveRecord>,
    #[serde(default)]
    run_dir: Option<String>,
}

fn verify(i: VerifyIn) -> R<Value> {
    let verdict = match (i.record, i.run_dir) {
        (Some(record), None) => verify_live(&record)?,
        (None, Some(dir)) => verify_live_dir(Path::new(&dir))?,
        _ => return Err("give exactly one of record or run_dir".into()),
    };
    to_value(verdict)
}

#[cfg(test)]
mod tests {
    /// Every op has its own section in the wire-format doc, and the doc names
    /// no op the CLI lacks.
    #[test]
    fn wire_format_doc_covers_exactly_the_ops() {
        let doc = include_str!("../../../docs/live/wire-format.md");
        let documented: Vec<&str> = doc
            .lines()
            .filter_map(|l| l.strip_prefix("### `"))
            .filter_map(|l| l.strip_suffix('`'))
            .collect();
        let mut want = super::OPS.to_vec();
        let mut got = documented.clone();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(got, want);
    }
}
