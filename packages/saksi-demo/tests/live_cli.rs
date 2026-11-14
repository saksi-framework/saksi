//! `saksi-demo live`: every op driven as a separate process, the way the
//! console, the trustee processes and the phone will drive them.
//!
//! Set `SAKSI_LIVE_FIXTURE_OUT=<path>` to make `full_pipeline_through_the_cli`
//! also write the chaincode-acceptance fixture the Go test
//! `TestLiveArtifactsPassTheChaincode` reads (or run
//! `tools/live/regen-chaincode-fixture.sh`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use curve25519_dalek::scalar::Scalar;
use serde_json::{json, Value};

use saksi_crypto::dkg::{combine_partial_decryptions, partial_decrypt, TrusteeShare};
use saksi_crypto::elgamal::{encrypt, Plaintext, PublicKey};

const T: usize = 3;
const N: usize = 5;

/// The committed chaincode fixture and its schema tag.
const FIXTURE: &str = "../saksi-protocol/test-vectors/live-v1/election.json";
const FIXTURE_SCHEMA: &str = "saksi-live-chaincode-fixture-v1";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_saksi-demo")
}

fn spawn(op: &str, input: &Value) -> std::process::Child {
    use std::io::Write;
    let mut child = Command::new(bin())
        .args(["live", op])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn saksi-demo");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    child
}

fn finish(op: &str, child: std::process::Child) -> Result<Value, String> {
    let out = child.wait_with_output().unwrap();
    if out.status.success() {
        assert!(out.stderr.is_empty(), "{op}: stderr on success");
        Ok(serde_json::from_slice(&out.stdout).expect("stdout is one JSON object"))
    } else {
        assert!(out.stdout.is_empty(), "{op}: stdout on failure");
        let err: Value = serde_json::from_slice(&out.stderr).expect("stderr is one JSON object");
        Err(err["error"].as_str().expect("error string").to_string())
    }
}

/// Runs `saksi-demo live <op>` with `input` on stdin. `Ok(stdout)` on exit 0,
/// `Err(stderr error)` otherwise; both parsed as one JSON object.
fn live(op: &str, input: &Value) -> Result<Value, String> {
    finish(op, spawn(op, input))
}

fn ok(op: &str, input: Value) -> Value {
    live(op, &input).unwrap_or_else(|e| panic!("{op} failed: {e}"))
}

fn tempdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "saksi-live-cli-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

fn mode(path: &str) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn issuer(dir: &Path) -> (String, String) {
    let key = p(dir, "issuer.key");
    let out = ok("issuer-keygen", json!({ "key_file": key }));
    assert_eq!(mode(&key), 0o600);
    (key, out["public_key"].as_str().unwrap().to_string())
}

fn params(election_id: &str, issuer_pk: &str) -> Value {
    ok(
        "election-params",
        json!({
            "election_id": election_id,
            "positions": [
                { "id": "president", "candidates": ["alice", "bob", "carol"] },
                { "id": "secretary", "candidates": ["dan", "eve", "fay"] },
            ],
            "trustees": N, "threshold": T, "issuer_public_key": issuer_pk,
        }),
    )
}

/// The issuer, the election parameters, five trustees' keygen and deal, and
/// the relay's view of it.
struct Ceremony {
    dir: PathBuf,
    issuer_key: String,
    issuer_pk: String,
    params: String,
    peers: Value,
    deals: Vec<Value>,
}

impl Ceremony {
    fn key(&self, id: usize) -> String {
        p(&self.dir, &format!("t{id}.key"))
    }
    fn share(&self, id: usize) -> String {
        p(&self.dir, &format!("t{id}.share"))
    }

    fn new(election_id: &str) -> Self {
        let dir = tempdir();
        let (issuer_key, issuer_pk) = issuer(&dir);
        let params = params(election_id, &issuer_pk)["params"]
            .as_str()
            .unwrap()
            .to_string();
        let mut c = Ceremony {
            dir,
            issuer_key,
            issuer_pk,
            params,
            peers: json!([]),
            deals: Vec::new(),
        };
        let peers: Vec<Value> = (1..=N)
            .map(|id| {
                let out = ok(
                    "trustee-keygen",
                    json!({ "trustee_id": id, "key_file": c.key(id) }),
                );
                assert_eq!(mode(&c.key(id)), 0o600);
                assert_eq!(out["fingerprint"].as_str().unwrap().len(), 19);
                json!({ "trustee_id": id, "receive_public_key": out["receive_public_key"] })
            })
            .collect();
        c.peers = Value::Array(peers);
        c.deals = (1..=N).map(|id| c.deal(id, &c.peers)).collect();
        c
    }

    fn deal(&self, id: usize, peers: &Value) -> Value {
        ok(
            "dkg-deal",
            json!({ "receive_key_file": self.key(id), "params": self.params,
                    "dealer_id": id, "peers": peers }),
        )
    }

    /// The `dkg-receive` input for `trustee`, with the shares addressed to
    /// `addressed_to` (normally the same trustee).
    fn receive_input(&self, trustee: usize, addressed_to: usize) -> Value {
        let dealers: Vec<Value> = self
            .deals
            .iter()
            .map(|d| {
                let id = d["dealer_id"].as_u64().unwrap() as usize;
                json!({
                    "dealer_id": id,
                    "receive_public_key": self.peers[id - 1]["receive_public_key"],
                    "commitments": d["commitments"],
                    "masked_share": d["masked_shares"][addressed_to - 1],
                })
            })
            .collect();
        json!({ "receive_key_file": self.key(trustee), "share_file": self.share(trustee),
                "params": self.params, "trustee_id": trustee,
                "peers": self.peers, "dealers": dealers })
    }

    fn receive_all(&self) -> Vec<Value> {
        (1..=N)
            .map(|id| {
                let out = ok("dkg-receive", self.receive_input(id, id));
                assert_eq!(mode(&self.share(id)), 0o600, "share file must be 0600");
                out
            })
            .collect()
    }

    fn transcript(&self) -> Value {
        let dealers: Vec<Value> = self
            .deals
            .iter()
            .map(|d| json!({ "dealer_id": d["dealer_id"], "commitments": d["commitments"] }))
            .collect();
        ok(
            "dkg-transcript",
            json!({ "params": self.params, "dealers": dealers }),
        )
    }

    fn share_scalar(&self, id: usize) -> Scalar {
        let f: Value =
            serde_json::from_str(&std::fs::read_to_string(self.share(id)).unwrap()).unwrap();
        let bytes: [u8; 32] = hex::decode(f["share"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        Scalar::from_canonical_bytes(bytes).unwrap()
    }
}

/// The five issuance ops, as the phone and the console run them.
fn issue(dir: &Path, voter: usize, issuer_key: &str, issuer_pk: &str) -> Value {
    let session = p(dir, &format!("session-{voter}"));
    let begin = ok("voter-begin", json!({}));
    let pre = ok(
        "issue-presign",
        json!({ "issuer_key_file": issuer_key, "blinded_commitment": begin["blinded_commitment"],
                "session_file": session }),
    );
    assert_eq!(mode(&session), 0o600);
    let blind = ok(
        "voter-blind",
        json!({ "state": begin["state"], "r": pre["r"], "issuer_public_key": issuer_pk }),
    );
    let sign_in = json!({ "issuer_key_file": issuer_key, "session_file": session,
                          "e_prime": blind["e_prime"] });
    let signed = ok("issue-sign", sign_in.clone());
    // The session is single-use: it is gone, and a second signature is refused.
    assert!(!Path::new(&session).exists());
    assert!(live("issue-sign", &sign_in)
        .unwrap_err()
        .contains("already used or missing"));
    ok(
        "voter-finalize",
        json!({ "state": blind["state"], "s_iss": signed["s_iss"], "issuer_public_key": issuer_pk }),
    )
}

fn point(hexstr: &str) -> curve25519_dalek::ristretto::RistrettoPoint {
    saksi_crypto::group::point_from_compressed(hex::decode(hexstr).unwrap().try_into().unwrap())
        .unwrap()
}

#[test]
fn dkg_as_five_processes() {
    let c = Ceremony::new("live-dkg");
    let dir = c.dir.clone();
    let received = c.receive_all();

    // Every trustee reports the same joint key, and it is the transcript's;
    // every trustee and every dealer report the same roster digest.
    let transcript = c.transcript();
    for r in &received {
        assert_eq!(r["joint_public_key"], transcript["joint_public_key"]);
        assert_eq!(r["roster_digest"], c.deals[0]["roster_digest"]);
        assert_eq!(r["roster_fingerprint"], c.deals[0]["roster_fingerprint"]);
    }
    for d in &c.deals {
        assert_eq!(d["roster_digest"], c.deals[0]["roster_digest"]);
    }
    // Each trustee's verification key is the one the transcript derives.
    for (k, r) in received.iter().enumerate() {
        assert_eq!(
            r["verification_key"],
            transcript["verification_keys"][k]["verification_key"]
        );
        assert_eq!(
            r["fingerprint"],
            transcript["verification_keys"][k]["fingerprint"]
        );
    }

    // Any 3 of the 5 shares open a ciphertext under the joint key.
    let pk = PublicKey::from_point(point(transcript["joint_public_key"].as_str().unwrap()));
    let message = Plaintext::from_small_integer(1);
    let ct = encrypt(&pk, message, Scalar::from(1234u64));
    let shares: Vec<TrusteeShare> = (1..=N)
        .map(|id| TrusteeShare {
            trustee_id: id,
            value: c.share_scalar(id),
        })
        .collect();
    let mut subsets = 0;
    for a in 0..N {
        for b in a + 1..N {
            for d in b + 1..N {
                let partials: Vec<_> = [a, b, d]
                    .iter()
                    .map(|&i| partial_decrypt(&shares[i], &ct))
                    .collect();
                assert_eq!(
                    combine_partial_decryptions(&ct, &partials).unwrap(),
                    message
                );
                subsets += 1;
            }
        }
    }
    assert_eq!(subsets, 10);

    // A relay that flips one bit of dealer 4's share to trustee 1 is caught,
    // and the dealer is named.
    let mut input = c.receive_input(1, 1);
    input["share_file"] = json!(p(&dir, "t1-again.share"));
    let ctext = input["dealers"][3]["masked_share"]["ciphertext"]
        .as_str()
        .unwrap()
        .to_string();
    let mut raw = hex::decode(ctext).unwrap();
    raw[5] ^= 0x10;
    input["dealers"][3]["masked_share"]["ciphertext"] = json!(hex::encode(raw));
    let err = live("dkg-receive", &input).unwrap_err();
    assert!(err.starts_with("dealer 4:"), "{err}");
    assert!(
        !Path::new(&p(&dir, "t1-again.share")).exists(),
        "no share file on refusal"
    );

    // A share masked for trustee 2 cannot be opened with trustee 3's key, even
    // when relabelled as addressed to trustee 3.
    let mut input = c.receive_input(3, 2);
    input["share_file"] = json!(p(&dir, "t3-from-2.share"));
    for d in input["dealers"].as_array_mut().unwrap() {
        d["masked_share"]["recipient_id"] = json!(3);
    }
    let err = live("dkg-receive", &input).unwrap_err();
    assert!(err.contains("failed authentication"), "{err}");

    // A share file is never overwritten.
    let err = live("dkg-receive", &c.receive_input(2, 2)).unwrap_err();
    assert!(err.contains("refusing to overwrite"), "{err}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_relay_that_substitutes_a_receive_key_is_caught() {
    let mut c = Ceremony::new("live-roster");
    // The relay generates its own receive key and shows dealers 1-4 a roster
    // with that key in trustee 5's place, so it could open their shares to 5.
    let relay_key = p(&c.dir, "relay.key");
    let relay = ok(
        "trustee-keygen",
        json!({ "trustee_id": 5, "key_file": relay_key }),
    );
    let mut forged = c.peers.clone();
    forged[4]["receive_public_key"] = relay["receive_public_key"].clone();
    let forged_deals: Vec<Value> = (1..=4).map(|id| c.deal(id, &forged)).collect();
    // The dealers who saw the forged roster report a different digest from the
    // genuine one, so comparing fingerprints exposes the substitution.
    assert_ne!(
        forged_deals[0]["roster_digest"],
        c.deals[0]["roster_digest"]
    );
    assert_ne!(
        forged_deals[0]["roster_fingerprint"],
        c.deals[0]["roster_fingerprint"]
    );
    // Trustee 5 itself will not deal under a roster without its own key.
    let err = live(
        "dkg-deal",
        &json!({ "receive_key_file": c.key(5), "params": c.params, "dealer_id": 5, "peers": forged }),
    )
    .unwrap_err();
    assert!(err.contains("not this dealer's key file"), "{err}");

    // A dealer key that is not the roster's key at that id is refused before
    // anything is unmasked.
    let mut input = c.receive_input(2, 2);
    input["dealers"][4]["receive_public_key"] = relay["receive_public_key"].clone();
    let err = live("dkg-receive", &input).unwrap_err();
    assert!(err.starts_with("dealer 5:"), "{err}");
    // Trustee 1 holds the genuine roster: every share masked under the forged
    // one fails its tag, and the first such dealer is named.
    c.deals.splice(0..4, forged_deals);
    let err = live("dkg-receive", &c.receive_input(1, 1)).unwrap_err();
    assert!(
        err.starts_with("dealer 1:") && err.contains("failed authentication"),
        "{err}"
    );
    // A duplicated key in the roster is refused.
    let mut dup = c.peers.clone();
    dup[3]["receive_public_key"] = dup[2]["receive_public_key"].clone();
    let err = live(
        "dkg-deal",
        &json!({ "receive_key_file": c.key(1), "params": c.params, "dealer_id": 1, "peers": dup }),
    )
    .unwrap_err();
    assert!(err.contains("repeats"), "{err}");
    let _ = std::fs::remove_dir_all(&c.dir);
}

#[test]
fn an_identity_joint_key_is_refused_by_transcript_and_ballot() {
    let c = Ceremony::new("live-identity");
    // Dealer 5 publishes the negation of the others' constant terms.
    let mut dealers: Vec<Value> = c
        .deals
        .iter()
        .map(|d| json!({ "dealer_id": d["dealer_id"], "commitments": d["commitments"] }))
        .collect();
    let others = (0..4).fold(
        curve25519_dalek::ristretto::RistrettoPoint::default(),
        |acc, k| acc + point(dealers[k]["commitments"][0].as_str().unwrap()),
    );
    dealers[4]["commitments"][0] = json!(hex::encode((-others).compress().to_bytes()));
    let err = live(
        "dkg-transcript",
        &json!({ "params": c.params, "dealers": dealers }),
    )
    .unwrap_err();
    assert!(err.contains("identity"), "{err}");

    // The phone refuses the same transcript if the console hands it over.
    let mut transcript: saksi_protocol::DKGTranscript = prost::Message::decode(
        hex::decode(c.transcript()["dkg"].as_str().unwrap())
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let others = (0..4).fold(
        curve25519_dalek::ristretto::RistrettoPoint::default(),
        |acc, k| {
            acc + point(&hex::encode(
                &transcript.trustee_commitments[k].coefficient_commitments[0],
            ))
        },
    );
    transcript.trustee_commitments[4].coefficient_commitments[0] =
        (-others).compress().to_bytes().to_vec();
    let credential = issue(&c.dir, 0, &c.issuer_key, &c.issuer_pk)["credential"].clone();
    let err = live(
        "ballot",
        &json!({ "params": c.params, "dkg": hex::encode(prost::Message::encode_to_vec(&transcript)),
                 "credential": credential, "position_id": "president", "choice": 0 }),
    )
    .unwrap_err();
    assert!(err.contains("identity"), "{err}");
    let _ = std::fs::remove_dir_all(&c.dir);
}

#[test]
fn issuance_through_the_five_ops_yields_a_presentable_credential() {
    let dir = tempdir();
    let (key, issuer_pk) = issuer(&dir);
    let fin = issue(&dir, 1, &key, &issuer_pk);
    let cred = &fin["credential"];
    let scalar = |v: &Value| {
        Scalar::from_canonical_bytes(
            <[u8; 32]>::try_from(hex::decode(v.as_str().unwrap()).unwrap()).unwrap(),
        )
        .unwrap()
    };
    let credential = saksi_credentials::Credential::from_parts(
        scalar(&cred["s_cred"]),
        point(cred["signature_r"].as_str().unwrap()),
        scalar(&cred["signature_s"]),
    );
    let pk = saksi_credentials::IssuerPublicKey(point(&issuer_pk));
    let presentation = credential.present(
        &pk,
        b"e",
        b"president",
        b"saksi-auditor-v1",
        &mut rand_core::OsRng,
    );
    saksi_credentials::verify_presentation(
        &presentation,
        &pk,
        b"e",
        b"president",
        b"saksi-auditor-v1",
    )
    .expect("presentation verifies");
    // Bound to the issuer: another issuer's key refuses it.
    let other_dir = tempdir();
    let (_, other) = issuer(&other_dir);
    let other = saksi_credentials::IssuerPublicKey(point(&other));
    assert!(saksi_credentials::verify_presentation(
        &presentation,
        &other,
        b"e",
        b"president",
        b"saksi-auditor-v1"
    )
    .is_err());
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(other_dir);
}

#[test]
fn two_concurrent_issue_signs_on_one_session_sign_once() {
    for round in 0..8 {
        let dir = tempdir();
        let (key, issuer_pk) = issuer(&dir);
        let session = p(&dir, "session");
        let begin = ok("voter-begin", json!({}));
        let pre = ok(
            "issue-presign",
            json!({ "issuer_key_file": key, "blinded_commitment": begin["blinded_commitment"],
                    "session_file": session }),
        );
        let blind = |_: usize| {
            ok(
                "voter-blind",
                json!({ "state": begin["state"], "r": pre["r"], "issuer_public_key": issuer_pk }),
            )
        };
        // Two different challenges on the same nonce: two answers would
        // reveal the issuer key.
        let (b1, b2) = (blind(1), blind(2));
        let a = spawn(
            "issue-sign",
            &json!({ "issuer_key_file": key, "session_file": session, "e_prime": b1["e_prime"] }),
        );
        let b = spawn(
            "issue-sign",
            &json!({ "issuer_key_file": key, "session_file": session, "e_prime": b2["e_prime"] }),
        );
        let results = [finish("issue-sign", a), finish("issue-sign", b)];
        let signed = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(signed, 1, "round {round}: {results:?}");
        let refused = results.iter().find_map(|r| r.as_ref().err()).unwrap();
        assert!(refused.contains("already used or missing"), "{refused}");
        // Nothing is left behind: neither the session nor a claimed copy.
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "only issuer.key"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Everything a finished election produced, for the negative tests and the
/// chaincode fixture.
struct Election {
    params: String,
    dkg: String,
    issuer_pk: String,
    ballots: Vec<Value>,
    partials_by_trustee: Vec<(usize, Vec<String>)>,
    totals: Vec<u64>,
    signatures: Vec<Value>,
    tally: String,
}

impl Election {
    fn ballot_hexes(&self) -> Vec<String> {
        self.ballots
            .iter()
            .map(|b| b["ballot"].as_str().unwrap().to_string())
            .collect()
    }
    fn all_partials(&self) -> Vec<String> {
        self.partials_by_trustee
            .iter()
            .flat_map(|(_, p)| p.clone())
            .collect()
    }
}

fn run_election(election_id: &str, choices: &[[usize; 2]]) -> (Election, Ceremony) {
    let c = Ceremony::new(election_id);
    c.receive_all();
    let dkg = c.transcript()["dkg"].as_str().unwrap().to_string();
    let params = c.params.clone();

    let mut ballots = Vec::new();
    for (v, picks) in choices.iter().enumerate() {
        let credential = issue(&c.dir, v, &c.issuer_key, &c.issuer_pk)["credential"].clone();
        for (position, &choice) in ["president", "secretary"].iter().zip(picks) {
            let b = ok(
                "ballot",
                json!({ "params": params, "dkg": dkg, "credential": credential,
                        "position_id": position, "choice": choice }),
            );
            let code = b["tracking_code"].as_str().unwrap();
            let nullifier = b["nullifier"].as_str().unwrap().to_uppercase();
            assert_eq!(code, format!("BC-{}-{}", &nullifier[..4], &nullifier[4..8]));
            ballots.push(b);
        }
    }
    let ballot_hex: Vec<&Value> = ballots.iter().map(|b| &b["ballot"]).collect();
    let aggregate = ok(
        "aggregate",
        json!({ "params": params, "dkg": dkg, "ballots": ballot_hex }),
    );
    assert_eq!(aggregate["ballot_count"], json!(choices.len() * 2));
    assert_eq!(
        aggregate["ballots_by_position"],
        json!({ "president": choices.len(), "secretary": choices.len() })
    );

    // Trustees 1, 3 and 5 decrypt; 2 and 4 stay away. Each aggregates the
    // ballot records itself and reports the same ballot-set digest.
    let partials_by_trustee: Vec<(usize, Vec<String>)> = [1usize, 3, 5]
        .iter()
        .map(|&t| {
            let out = ok(
                "partial",
                json!({ "share_file": c.share(t), "params": params, "dkg": dkg, "ballots": ballot_hex }),
            );
            assert_eq!(out["trustee_id"], json!(t.to_string()));
            assert_eq!(out["ballots_digest"], aggregate["ballots_digest"]);
            assert_eq!(out["ballot_count"], aggregate["ballot_count"]);
            let ps = out["partials"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["partial"].as_str().unwrap().to_string())
                .collect();
            (t, ps)
        })
        .collect();
    let all_partials: Vec<&String> = partials_by_trustee.iter().flat_map(|(_, p)| p).collect();
    let combined = ok(
        "combine",
        json!({ "params": params, "dkg": dkg, "ballots": ballot_hex, "partials": all_partials }),
    );
    let totals: Vec<u64> = serde_json::from_value(combined["totals"].clone()).unwrap();

    let signatures: Vec<Value> = [1usize, 3, 5]
        .iter()
        .map(|&t| {
            let s = ok(
                "sign-tally",
                json!({ "share_file": c.share(t), "params": params, "dkg": dkg, "ballots": ballot_hex,
                        "partials": all_partials, "totals": totals }),
            );
            assert_eq!(s["ballots_digest"], aggregate["ballots_digest"]);
            json!({ "trustee_id": s["trustee_id"], "signature": s["signature"] })
        })
        .collect();
    let assembled = ok(
        "tally-assemble",
        json!({ "params": params, "dkg": dkg, "ballots": ballot_hex, "partials": all_partials,
                "totals": totals, "signatures": signatures }),
    );
    assert_eq!(assembled["meets_threshold"], json!(true));
    let issuer_pk = c.issuer_pk.clone();
    (
        Election {
            params,
            dkg,
            issuer_pk,
            ballots,
            partials_by_trustee,
            totals,
            signatures,
            tally: assembled["tally"].as_str().unwrap().to_string(),
        },
        c,
    )
}

fn record(e: &Election, ballots: Vec<String>, expected: Option<usize>) -> Value {
    let mut r = json!({ "record": {
        "params": e.params, "dkg": e.dkg, "issuer_public_key": e.issuer_pk,
        "ballots": ballots, "partial_decryptions": e.all_partials(), "tally": e.tally,
    }});
    if let Some(n) = expected {
        r["record"]["expected_ballots"] = json!(n);
    }
    r
}

fn failed(verdict: &Value) -> Vec<String> {
    verdict["failed_checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["check"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn full_pipeline_through_the_cli() {
    // 3 voters x 2 positions x 3 candidates.
    let choices = [[0, 2], [1, 2], [0, 0]];
    let (e, c) = run_election("live-e2e", &choices);
    // president: alice 2, bob 1, carol 0; secretary: dan 1, eve 0, fay 2.
    assert_eq!(e.totals, vec![2, 1, 0, 1, 0, 2]);

    let verdict = ok("verify-live", record(&e, e.ballot_hexes(), Some(6)));
    assert_eq!(verdict["overall"], "pass", "{verdict:#}");
    for (k, v) in verdict["summary"].as_object().unwrap() {
        assert_eq!(v, "pass", "{k}");
    }
    assert_eq!(verdict["summary"].as_object().unwrap().len(), 5);
    assert_eq!(verdict["ballots"], json!(6));
    assert_eq!(
        verdict["ballots_verified"],
        json!({ "total": 6, "by_position": { "president": 3, "secretary": 3 } })
    );
    for (row, t) in verdict["contests"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&e.totals)
    {
        assert_eq!(row["decoded"], json!(t));
        assert_eq!(row["published_tally"], json!(t));
    }

    // The same record as a run folder (header.json + ballots.ndjson).
    let run = c.dir.join("run");
    std::fs::create_dir_all(&run).unwrap();
    let header = json!({
        "election_id": "live-e2e", "params": e.params, "dkg": e.dkg, "issuer_pk": e.issuer_pk,
        "binding_context": hex::encode(b"saksi-auditor-v1"), "partial_decryptions": e.all_partials(),
        "tally": e.tally, "ground_truth": [], "voter_ids": [], "positions": 2, "candidates": 3,
        "n": e.ballots.len(),
    });
    std::fs::write(run.join("header.json"), header.to_string()).unwrap();
    std::fs::write(
        run.join("ballots.ndjson"),
        e.ballot_hexes().join("\n") + "\n",
    )
    .unwrap();
    let verdict = ok("verify-live", json!({ "run_dir": run.to_string_lossy() }));
    assert_eq!(verdict["overall"], "pass", "{verdict:#}");
    assert_eq!(verdict["ballots_verified"]["total"], json!(6));

    if let Ok(path) = std::env::var("SAKSI_LIVE_FIXTURE_OUT") {
        write_fixture(&path, &e);
    }
    let _ = std::fs::remove_dir_all(&c.dir);
}

#[test]
fn negative_paths_are_refused_or_reported() {
    let (e, c) = run_election("live-neg", &[[0, 1], [2, 1]]);
    let ballots = e.ballot_hexes();
    let all = e.all_partials();

    // Two partials are below the threshold of three.
    let two: Vec<&String> = e.partials_by_trustee[..2]
        .iter()
        .flat_map(|(_, p)| p)
        .collect();
    let err = live(
        "combine",
        &json!({ "params": e.params, "dkg": e.dkg, "ballots": ballots, "partials": two }),
    )
    .unwrap_err();
    assert!(err.contains("decryption.threshold"), "{err}");

    // One changed byte in a ballot's ciphertext fails the CDS / selection check.
    let mut tampered = ballots.clone();
    let mut b: saksi_protocol::Ballot =
        prost::Message::decode(hex::decode(&tampered[1]).unwrap().as_slice()).unwrap();
    b.ciphertexts[0].data[7] ^= 0x01;
    tampered[1] = hex::encode(prost::Message::encode_to_vec(&b));
    let verdict = ok("verify-live", record(&e, tampered.clone(), None));
    assert_eq!(verdict["overall"], "fail");
    let f = failed(&verdict);
    assert!(
        f.iter().any(|c| c == "ballot.cds_proof"
            || c == "ballot.selection_sum"
            || c == "ballot.decode"),
        "{f:?}"
    );
    assert_eq!(verdict["summary"]["ballot_proofs"], "fail");
    assert_eq!(verdict["ballots_verified"]["total"], json!(3));
    // The trustee-side ops refuse the same ballot outright, and decrypt
    // nothing.
    assert!(live(
        "aggregate",
        &json!({ "params": e.params, "dkg": e.dkg, "ballots": tampered })
    )
    .is_err());
    let err = live(
        "partial",
        &json!({ "share_file": c.share(2), "params": e.params, "dkg": e.dkg, "ballots": tampered }),
    )
    .unwrap_err();
    assert!(err.contains("ballot[1]"), "{err}");

    // An empty ballot list is not decrypted.
    let err = live(
        "partial",
        &json!({ "share_file": c.share(2), "params": e.params, "dkg": e.dkg, "ballots": [] }),
    )
    .unwrap_err();
    assert!(err.contains("empty"), "{err}");

    // A duplicated ballot is reported as a repeated nullifier.
    let mut dup = ballots.clone();
    dup.push(dup[0].clone());
    let verdict = ok("verify-live", record(&e, dup.clone(), None));
    assert_eq!(verdict["overall"], "fail");
    assert!(
        failed(&verdict).contains(&"nullifier.unique".to_string()),
        "{verdict:#}"
    );
    assert_eq!(verdict["summary"]["nullifiers_unique"], "fail");
    let err = live(
        "aggregate",
        &json!({ "params": e.params, "dkg": e.dkg, "ballots": dup }),
    )
    .unwrap_err();
    assert!(err.contains("nullifier"), "{err}");

    // An omitted ballot fails completeness when the chain's count is given.
    let verdict = ok("verify-live", record(&e, ballots[1..].to_vec(), Some(4)));
    assert!(
        failed(&verdict).contains(&"stream.completeness".to_string()),
        "{verdict:#}"
    );

    // A trustee will not sign totals its own aggregate does not decrypt to.
    let mut wrong = e.totals.clone();
    wrong[0] += 1;
    let err = live(
        "sign-tally",
        &json!({ "share_file": c.share(2), "params": e.params, "dkg": e.dkg, "ballots": ballots,
                 "partials": all, "totals": wrong }),
    )
    .unwrap_err();
    assert!(err.contains("differ"), "{err}");
    // Nor the right totals over a ballot set the partials were not made for.
    let err = live(
        "sign-tally",
        &json!({ "share_file": c.share(2), "params": e.params, "dkg": e.dkg,
                 "ballots": ballots[1..], "partials": all, "totals": e.totals }),
    )
    .unwrap_err();
    assert!(err.contains("decryption.cp_proof"), "{err}");

    // A tally with two signatures assembles but says it is below threshold.
    let assembled = ok(
        "tally-assemble",
        json!({ "params": e.params, "dkg": e.dkg, "ballots": ballots, "partials": all,
                "totals": e.totals, "signatures": e.signatures[..2] }),
    );
    assert_eq!(assembled["meets_threshold"], json!(false));

    // A secret file another user can read is refused.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(c.share(1), std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = live(
        "partial",
        &json!({ "share_file": c.share(1), "params": e.params, "dkg": e.dkg, "ballots": ballots }),
    )
    .unwrap_err();
    assert!(err.contains("readable by other users"), "{err}");
    let _ = std::fs::remove_dir_all(&c.dir);
}

/// The committed chaincode fixture still matches the current wire format: its
/// schema tag is current and its on-chain record still passes `verify-live`.
/// If this fails, regenerate it with `tools/live/regen-chaincode-fixture.sh`.
#[test]
fn committed_chaincode_fixture_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    let f: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        f["schema"], FIXTURE_SCHEMA,
        "stale fixture: run tools/live/regen-chaincode-fixture.sh"
    );
    let n = f["ballots"].as_array().unwrap().len();
    let verdict = ok(
        "verify-live",
        json!({ "record": {
            "params": f["params"], "dkg": f["dkg"], "issuer_public_key": f["issuer_public_key"],
            "ballots": f["ballots"], "partial_decryptions": f["partials"],
            "tally": f["tally_three_signatures"], "expected_ballots": n,
        }}),
    );
    assert_eq!(
        verdict["overall"], "pass",
        "stale fixture: run tools/live/regen-chaincode-fixture.sh\n{verdict:#}"
    );
}

/// The Go chaincode test's input: every artifact a live election hands
/// `CreateElection` .. `PublishTally`, produced by the CLI above.
fn write_fixture(path: &str, e: &Election) {
    let two_sig = ok(
        "tally-assemble",
        json!({ "params": e.params, "dkg": e.dkg, "ballots": e.ballot_hexes(),
                "partials": e.all_partials(), "totals": e.totals,
                "signatures": e.signatures[..2] }),
    );
    let fixture = json!({
        "schema": FIXTURE_SCHEMA,
        "comment": "Produced by tools/live/regen-chaincode-fixture.sh: every artifact is saksi-demo live output.",
        "election_id": "live-e2e",
        "params": e.params,
        "dkg": e.dkg,
        "issuer_public_key": e.issuer_pk,
        "ballots": e.ballot_hexes(),
        "partials": e.all_partials(),
        "totals": e.totals,
        "tally_three_signatures": e.tally,
        "tally_two_signatures": two_sig["tally"],
    });
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}
