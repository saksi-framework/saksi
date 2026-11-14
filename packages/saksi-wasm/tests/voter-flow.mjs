// Runs the phone's WebAssembly under node against the native CLI as issuer
// and trustees: a real 5-trustee DKG, blind issuance with the voter's steps
// in wasm, ballots built in wasm, the Benaloh challenge, and the full tally
// and audit with ballots from two CLI voters alongside.
//
// Run by tools/live/test-wasm.sh, which builds the package and the CLI and
// then runs the chaincode test over the fixture this script writes.
//
// Env:
//   SAKSI_DEMO           path to the saksi-demo binary
//   SAKSI_WASM_PKG       packages/saksi-wasm/pkg (the web package the app imports)
//   SAKSI_WASM_PKG_NODE  packages/saksi-wasm/pkg-node (wasm-bindgen nodejs target)
//   SAKSI_WASM_FIXTURE   where to write the chaincode fixture
//   SAKSI_WASM_TIMINGS   optional: where to write the timings as JSON

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const env = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set`);
  return v;
};
const DEMO = env("SAKSI_DEMO");
const PKG = env("SAKSI_WASM_PKG");
const PKG_NODE = env("SAKSI_WASM_PKG_NODE");
const FIXTURE = env("SAKSI_WASM_FIXTURE");

const FIXTURE_SCHEMA = "saksi-live-wasm-fixture-v1";
const T = 3;
const N = 5;
const ELECTION = "live-wasm";
const POSITIONS = [
  { id: "president", candidates: ["alice", "bob", "carol"] },
  { id: "secretary", candidates: ["dan", "eve", "fay"] },
];

let passed = 0;
const check = (name, fn) => {
  fn();
  passed += 1;
  console.log(`ok   ${name}`);
};

// ---------------------------------------------------------------------------
// The native CLI.
// ---------------------------------------------------------------------------

function run(op, input) {
  const r = spawnSync(DEMO, ["live", op], { input: JSON.stringify(input) });
  return r;
}
function cli(op, input) {
  const r = run(op, input);
  if (r.status !== 0) throw new Error(`saksi-demo live ${op} failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "saksi-wasm-flow-"));
const file = (name) => path.join(dir, name);

// ---------------------------------------------------------------------------
// The package, loaded the way the app loads it (the web build and its typed
// wrapper), with the module bytes handed to init instead of fetched.
// ---------------------------------------------------------------------------

const t0 = performance.now();
const saksi = await import(pathToFileURL(path.join(PKG, "index.js")).href);
await saksi.default({ module_or_path: fs.readFileSync(path.join(PKG, "saksi_wasm_bg.wasm")) });
const initMs = performance.now() - t0;

// The output shapes, read from wire.d.ts (one field per line), so the types
// the app compiles against are held to what the wasm actually returns.
const interfaces = {};
const dts = fs.readFileSync(path.join(PKG, "wire.d.ts"), "utf8");
for (const m of dts.matchAll(/export interface (\w+) \{([^}]*)\}/g)) {
  interfaces[m[1]] = [...m[2].matchAll(/^\s*(\w+)\??:/gm)].map((f) => f[1]).sort();
}
function shape(name, value) {
  assert.ok(interfaces[name], `wire.d.ts has no interface ${name}`);
  assert.deepEqual(Object.keys(value).sort(), interfaces[name], `${name} keys`);
}

function thrown(fn) {
  try {
    fn();
  } catch (e) {
    const body = JSON.parse(e.message); // {"error": "..."}
    assert.deepEqual(Object.keys(body), ["error"]);
    assert.equal(saksi.errorOf(e), body.error);
    return body.error;
  }
  throw new Error("expected a thrown error");
}

const timings = {};
function timed(name, fn) {
  const start = performance.now();
  const out = fn();
  (timings[name] ??= []).push(performance.now() - start);
  return out;
}

// ---------------------------------------------------------------------------
// Issuer, election, and a real 5-trustee DKG, all through the CLI.
// ---------------------------------------------------------------------------

const issuerKey = file("issuer.key");
const issuerPk = cli("issuer-keygen", { key_file: issuerKey }).public_key;
const params = cli("election-params", {
  election_id: ELECTION,
  positions: POSITIONS,
  trustees: N,
  threshold: T,
  issuer_public_key: issuerPk,
}).params;

const peers = [];
for (let id = 1; id <= N; id++) {
  const out = cli("trustee-keygen", { trustee_id: id, key_file: file(`t${id}.key`) });
  peers.push({ trustee_id: id, receive_public_key: out.receive_public_key });
}
const deals = [];
for (let id = 1; id <= N; id++) {
  deals.push(
    cli("dkg-deal", { receive_key_file: file(`t${id}.key`), params, dealer_id: id, peers }),
  );
}
const received = [];
for (let id = 1; id <= N; id++) {
  received.push(
    cli("dkg-receive", {
      receive_key_file: file(`t${id}.key`),
      share_file: file(`t${id}.share`),
      params,
      trustee_id: id,
      peers,
      dealers: deals.map((d) => ({
        dealer_id: d.dealer_id,
        receive_public_key: peers[d.dealer_id - 1].receive_public_key,
        commitments: d.commitments,
        masked_share: d.masked_shares[id - 1],
      })),
    }),
  );
}
const transcript = cli("dkg-transcript", {
  params,
  dealers: deals.map((d) => ({ dealer_id: d.dealer_id, commitments: d.commitments })),
});
const dkg = transcript.dkg;

check("version names the build and the wire format", () => {
  const v = saksi.version();
  shape("VersionOutput", v);
  assert.equal(v.name, "saksi-wasm");
  assert.equal(v.wire_format, "saksi-live-wire-v1");
  console.log(`     ${JSON.stringify(v)}`);
});

check("election_info: positions, and the joint-key fingerprint the trustees show", () => {
  const info = timed("election_info", () => saksi.election_info({ params, dkg }));
  shape("ElectionInfoOutput", info);
  info.positions.forEach((p) => shape("Position", p));
  assert.deepEqual(info.positions, POSITIONS);
  assert.equal(info.trustees, N);
  assert.equal(info.threshold, T);
  assert.equal(info.issuer_public_key, issuerPk);
  assert.equal(info.joint_public_key, transcript.joint_public_key);
  assert.equal(info.joint_key_fingerprint, transcript.joint_key_fingerprint);
  for (const r of received) assert.equal(r.joint_key_fingerprint, info.joint_key_fingerprint);
  assert.match(info.joint_key_fingerprint, /^([0-9A-F]{4}-){7}[0-9A-F]{4}$/);
});

// ---------------------------------------------------------------------------
// Issuance: the voter's three steps in wasm, the issuer's two in the CLI.
// ---------------------------------------------------------------------------

function wasmIssue(tag) {
  const session = file(`session-${tag}`);
  const begin = timed("begin_issuance", () => saksi.begin_issuance());
  const pre = cli("issue-presign", {
    issuer_key_file: issuerKey,
    blinded_commitment: begin.blinded_commitment,
    session_file: session,
  });
  const blind = timed("blind_challenge", () =>
    saksi.blind_challenge({ state: begin.state, r: pre.r, issuer_public_key: issuerPk }),
  );
  const signed = cli("issue-sign", {
    issuer_key_file: issuerKey,
    session_file: session,
    e_prime: blind.e_prime,
  });
  const fin = timed("finalize_issuance", () =>
    saksi.finalize_issuance({ state: blind.state, s_iss: signed.s_iss, issuer_public_key: issuerPk }),
  );
  return { begin, blind, fin };
}

function cliIssue(tag) {
  const session = file(`session-${tag}`);
  const begin = cli("voter-begin", {});
  const pre = cli("issue-presign", {
    issuer_key_file: issuerKey,
    blinded_commitment: begin.blinded_commitment,
    session_file: session,
  });
  const blind = cli("voter-blind", { state: begin.state, r: pre.r, issuer_public_key: issuerPk });
  const signed = cli("issue-sign", {
    issuer_key_file: issuerKey,
    session_file: session,
    e_prime: blind.e_prime,
  });
  return cli("voter-finalize", { state: blind.state, s_iss: signed.s_iss, issuer_public_key: issuerPk })
    .credential;
}

const voter = wasmIssue("wasm");
let credential;
check("issuance: begin, blind and finalize run in wasm against the CLI issuer", () => {
  shape("BeginIssuanceOutput", voter.begin);
  shape("BlindState", voter.begin.state);
  shape("BlindChallengeOutput", voter.blind);
  shape("FinalizeState", voter.blind.state);
  shape("FinalizeIssuanceOutput", voter.fin);
  shape("Credential", voter.fin.credential);
  // Stored the way IndexedDB stores it: structured-cloned JSON.
  const stored = JSON.stringify(voter.fin.credential);
  credential = structuredClone(JSON.parse(stored));
});

check("check_credential accepts the stored credential for this election", () => {
  const ok = timed("check_credential", () => saksi.check_credential({ params, credential }));
  shape("CheckCredentialOutput", ok);
  assert.equal(ok.usable, true);
  assert.equal(ok.election_id, ELECTION);
  assert.equal(ok.issuer_public_key, issuerPk);
  assert.equal(ok.commitment, voter.fin.commitment);
});

check("check_credential refuses it for an election with another issuer", () => {
  const otherPk = cli("issuer-keygen", { key_file: file("other-issuer.key") }).public_key;
  const otherParams = cli("election-params", {
    election_id: "live-wasm-other",
    positions: POSITIONS,
    trustees: N,
    threshold: T,
    issuer_public_key: otherPk,
  }).params;
  const err = thrown(() => saksi.check_credential({ params: otherParams, credential }));
  assert.match(err, /not signed by this election's issuer/);
  assert.ok(!err.includes(credential.s_cred));
});

check("a response from the wrong issuer session is refused in finalize", () => {
  const begin = saksi.begin_issuance();
  const pre = cli("issue-presign", {
    issuer_key_file: issuerKey,
    blinded_commitment: begin.blinded_commitment,
    session_file: file("session-wrong"),
  });
  const blind = saksi.blind_challenge({ state: begin.state, r: pre.r, issuer_public_key: issuerPk });
  const wrong = "01" + "00".repeat(31);
  const err = thrown(() =>
    saksi.finalize_issuance({ state: blind.state, s_iss: wrong, issuer_public_key: issuerPk }),
  );
  assert.match(err, /does not unblind into a valid signature/);
});

check("errors name no secret, even for malformed input", () => {
  const s = voter.begin.state.s_cred;
  const err = thrown(() => saksi.raw.blind_challenge(`{"state": {"s_cred": "${s}", "b": 7}}`));
  assert.match(err, /^input is the wrong shape/);
  assert.ok(!err.includes(s));
  const err2 = thrown(() => saksi.raw.finalize_issuance(`{"state": "${s}`));
  assert.ok(!err2.includes(s));
});

// More issuance rounds, for the timings only.
for (let i = 0; i < 4; i++) wasmIssue(`timing-${i}`);

// ---------------------------------------------------------------------------
// Ballots: two from the wasm voter, four from two CLI voters.
// ---------------------------------------------------------------------------

const choices = { wasm: [1, 2], b: [0, 2], c: [0, 0] };
const wasmBallots = POSITIONS.map((p, k) =>
  timed("build_ballot", () =>
    saksi.build_ballot({ params, dkg, credential, position_id: p.id, choice: choices.wasm[k] }),
  ),
);
check("build_ballot in wasm: the CLI ballot output plus an opening", () => {
  for (const b of wasmBallots) {
    shape("BuildBallotOutput", b);
    shape("BallotOpening", b.opening);
    assert.equal(b.election_id, ELECTION);
    assert.equal(b.opening.randomness.length, 3);
    const tc = saksi.tracking_code({ nullifier: b.nullifier });
    shape("TrackingCodeOutput", tc);
    assert.equal(tc.tracking_code, b.tracking_code);
    const n = b.nullifier.toUpperCase();
    assert.equal(b.tracking_code, `BC-${n.slice(0, 4)}-${n.slice(4, 8)}`);
  }
});

const cliBallots = [];
for (const tag of ["b", "c"]) {
  const cred = cliIssue(tag);
  POSITIONS.forEach((p, k) =>
    cliBallots.push(
      cli("ballot", { params, dkg, credential: cred, position_id: p.id, choice: choices[tag][k] }),
    ),
  );
}
const ballots = [...wasmBallots.map((b) => b.ballot), ...cliBallots.map((b) => b.ballot)];

// More ballots, for the timings only (one position, three candidates).
for (let i = 0; i < 9; i++) {
  timed("build_ballot", () =>
    saksi.build_ballot({ params, dkg, credential, position_id: "president", choice: i % 3 }),
  );
}

// ---------------------------------------------------------------------------
// Benaloh challenge.
// ---------------------------------------------------------------------------

const challenged = saksi.build_ballot({ params, dkg, credential, position_id: "president", choice: 0 });
let opened;
check("benaloh_open + benaloh_check pass for an honest ballot and name the candidate", () => {
  opened = timed("benaloh_open", () =>
    saksi.benaloh_open({ ballot: challenged.ballot, opening: challenged.opening }),
  );
  shape("BenalohOpened", opened);
  opened.slots.forEach((s) => shape("OpenedSlot", s));
  assert.equal(opened.nullifier, challenged.nullifier);
  // Same voter, same position: the same nullifier as the cast president ballot.
  assert.equal(opened.nullifier, wasmBallots[0].nullifier);
  const v = timed("benaloh_check", () =>
    saksi.benaloh_check({ params, dkg, ballot: challenged.ballot, opened }),
  );
  shape("BenalohCheckOutput", v);
  v.slots.forEach((s) => shape("SlotCheck", s));
  assert.equal(v.valid, true);
  assert.equal(v.encoded_choice, 0);
  assert.equal(v.encoded_candidate, "alice");
  assert.ok(v.slots.every((s) => s.reproduces));
  // The native CLI, independent of the phone's code, agrees.
  assert.deepEqual(cli("benaloh-check", { params, dkg, ballot: challenged.ballot, opened }), v);
});

check("benaloh_check fails a tampered opening (randomness or candidate)", () => {
  const badR = structuredClone(opened);
  const r = badR.slots[1].randomness;
  badR.slots[1].randomness = (r[0] === "0" ? "1" : "0") + r.slice(1);
  const v1 = saksi.benaloh_check({ params, dkg, ballot: challenged.ballot, opened: badR });
  assert.equal(v1.valid, false);
  assert.equal(v1.slots[1].reproduces, false);
  assert.equal(v1.encoded_candidate, null);
  assert.equal(cli("benaloh-check", { params, dkg, ballot: challenged.ballot, opened: badR }).valid, false);

  const badC = structuredClone(opened);
  badC.slots[0].plaintext = 0;
  badC.slots[1].plaintext = 1;
  const v2 = saksi.benaloh_check({ params, dkg, ballot: challenged.ballot, opened: badC });
  assert.equal(v2.valid, false);
  assert.equal(v2.encoded_candidate, null);
});

check("benaloh_open refuses an opening for another ballot", () => {
  const err = thrown(() =>
    saksi.benaloh_open({ ballot: wasmBallots[0].ballot, opening: challenged.opening }),
  );
  assert.match(err, /not for this ballot/);
});

// ---------------------------------------------------------------------------
// Tally and audit, through the CLI, over the wasm and CLI ballots together.
// ---------------------------------------------------------------------------

const aggregate = cli("aggregate", { params, dkg, ballots });
check("the CLI aggregates the wasm ballots with the CLI ones", () => {
  assert.equal(aggregate.ballot_count, 6);
  assert.deepEqual(aggregate.ballots_by_position, { president: 3, secretary: 3 });
});

const decrypting = [1, 3, 5];
const partialsByTrustee = decrypting.map((t) => {
  const out = cli("partial", { share_file: file(`t${t}.share`), params, dkg, ballots });
  assert.equal(out.ballots_digest, aggregate.ballots_digest);
  return out.partials.map((p) => p.partial);
});
const partials = partialsByTrustee.flat();
const combined = cli("combine", { params, dkg, ballots, partials });
// president: alice 2, bob 1, carol 0; secretary: dan 1, eve 0, fay 2.
const expected = [2, 1, 0, 1, 0, 2];
check("3 partials combine to totals equal to the choices", () => {
  assert.deepEqual(combined.totals, expected);
});

const signatures = decrypting.map((t) => {
  const s = cli("sign-tally", {
    share_file: file(`t${t}.share`),
    params,
    dkg,
    ballots,
    partials,
    totals: combined.totals,
  });
  return { trustee_id: s.trustee_id, signature: s.signature };
});
const assembled = cli("tally-assemble", {
  params,
  dkg,
  ballots,
  partials,
  totals: combined.totals,
  signatures,
});
const twoSig = cli("tally-assemble", {
  params,
  dkg,
  ballots,
  partials,
  totals: combined.totals,
  signatures: signatures.slice(0, 2),
});

check("verify-live passes the election with 3 signatures", () => {
  assert.equal(assembled.meets_threshold, true);
  const verdict = cli("verify-live", {
    record: {
      params,
      dkg,
      issuer_public_key: issuerPk,
      ballots,
      partial_decryptions: partials,
      tally: assembled.tally,
      expected_ballots: 6,
    },
  });
  assert.equal(verdict.overall, "pass", JSON.stringify(verdict.failed_checks));
  for (const [k, v] of Object.entries(verdict.summary)) assert.equal(v, "pass", k);
  assert.equal(verdict.ballots_verified.total, 6);
  verdict.contests.forEach((c, i) => {
    assert.equal(c.decoded, expected[i]);
    assert.equal(c.published_tally, expected[i]);
  });
  assert.ok(verdict.checks.some((c) => c.check === "live.joint_key_nonidentity" && c.status === "pass"));
});

check("verify-live fails a wasm ballot with one changed byte", () => {
  const tampered = [...ballots];
  const b = tampered[0];
  // Flip one hex digit near the end (inside the selection proof).
  const i = b.length - 10;
  tampered[0] = b.slice(0, i) + (b[i] === "0" ? "1" : "0") + b.slice(i + 1);
  const verdict = cli("verify-live", {
    record: {
      params,
      dkg,
      issuer_public_key: issuerPk,
      ballots: tampered,
      partial_decryptions: partials,
      tally: assembled.tally,
    },
  });
  assert.equal(verdict.overall, "fail");
  assert.equal(verdict.summary.ballot_proofs, "fail");
});

// ---------------------------------------------------------------------------
// The nodejs build: the same module under wasm-bindgen's other target.
// ---------------------------------------------------------------------------

check("the nodejs build loads and runs", () => {
  const require = createRequire(import.meta.url);
  const nodePkg = require(path.join(PKG_NODE, "saksi_wasm.js"));
  const v = JSON.parse(nodePkg.version());
  assert.equal(v.wire_format, "saksi-live-wire-v1");
  const b = JSON.parse(
    nodePkg.build_ballot(
      JSON.stringify({ params, dkg, credential, position_id: "secretary", choice: 1 }),
    ),
  );
  // Its ballot passes the native per-ballot checks too.
  const agg = cli("aggregate", { params, dkg, ballots: [b.ballot] });
  assert.equal(agg.ballot_count, 1);
});

// ---------------------------------------------------------------------------
// The chaincode fixture and the timings.
// ---------------------------------------------------------------------------

fs.writeFileSync(
  FIXTURE,
  JSON.stringify(
    {
      schema: FIXTURE_SCHEMA,
      comment:
        "Produced by tools/live/test-wasm.sh: ballots 0 and 1 were built by @saksi/wasm under node, the rest by saksi-demo live. Regenerate with tools/live/test-wasm.sh --write-fixture.",
      election_id: ELECTION,
      params,
      dkg,
      issuer_public_key: issuerPk,
      ballots,
      wasm_ballots: [0, 1],
      challenged_ballot: challenged.ballot,
      partials,
      totals: combined.totals,
      tally_three_signatures: assembled.tally,
      tally_two_signatures: twoSig.tally,
    },
    null,
    2,
  ) + "\n",
);

const stats = (xs) => {
  const sorted = [...xs].sort((a, b) => a - b);
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  return {
    n: xs.length,
    mean_ms: +mean.toFixed(2),
    median_ms: +sorted[Math.floor(sorted.length / 2)].toFixed(2),
    min_ms: +sorted[0].toFixed(2),
    max_ms: +sorted[sorted.length - 1].toFixed(2),
  };
};
const summary = { init_ms: +initMs.toFixed(2) };
for (const [k, xs] of Object.entries(timings)) summary[k] = stats(xs);
console.log(`\ntimings on ${os.cpus()[0].model}, node ${process.version} (wasm only; CLI calls excluded):`);
console.log(`  init (compile + instantiate)  ${summary.init_ms} ms`);
for (const [k, s] of Object.entries(summary)) {
  if (k === "init_ms") continue;
  console.log(
    `  ${k.padEnd(28)} n=${String(s.n).padStart(2)}  mean ${s.mean_ms} ms  median ${s.median_ms} ms  min ${s.min_ms} ms  max ${s.max_ms} ms`,
  );
}
if (process.env.SAKSI_WASM_TIMINGS) {
  fs.writeFileSync(process.env.SAKSI_WASM_TIMINGS, JSON.stringify(summary, null, 2) + "\n");
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n${passed} checks passed; fixture written to ${FIXTURE}`);
