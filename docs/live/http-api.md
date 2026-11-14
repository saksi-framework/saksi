# Live election HTTP API (`saksi-campaign serve --live`)

The console's routes for one live election: the presenter sets it up, the
trustee processes run the key ceremony and the decryption through it, the
phones enrol and vote through it, and anyone reads the record back from the
chain. The phone app (`apps/vote`) and the trustee process
(`saksi-campaign trustee --id N`) are written from this file.

All cryptography is `saksi-demo live <op>` (see `wire-format.md`). The console
passes the phone's and the trustees' payloads through in the wire-format
shapes: where a request body below says "the `<op>` output", post that op's
JSON output as it is. This is a later build, not the study build; the study's
routes and their output are unchanged.

## Starting the console

```
saksi-campaign serve --live --auth-file accounts.json --trustee-tokens tokens.json \
    --tls-cert fullchain.pem --tls-key privkey.pem --addr 0.0.0.0:8443 \
    --allow-host vote.vancornelio.dev \
    --demo /path/to/saksi-demo \
    --fabric-tls-cert ... --fabric-cert ... --fabric-key ...
```

- `--tls-cert` and `--tls-key` together serve HTTPS (TLS 1.2 minimum). The
  session cookie is then `Secure`.
- `--live` refuses to start without `--auth-file`. Without TLS it starts only
  on a loopback `--addr` (`127.0.0.1`, `::1`, `localhost`) and prints a
  warning.
- `--live` needs `--trustee-tokens` (env `SAKSI_TRUSTEE_TOKENS`).
- On start the console loads the newest live election in `--runs` and resumes
  it from disk and the chain (see **Restart**).

### Accounts (`--auth-file`)

The existing users file, with a third role:

```json
[{"username": "ban",    "role": "admin",   "password_bcrypt": "$2a$12$..."},
 {"username": "voter1", "role": "voter",   "password_bcrypt": "$2a$12$..."}]
```

Every `voter` account is on the voter roll. A voter has no `trustee_id`.
Hashes come from `saksi-campaign hash-password < password`. A voter account
can use only the issuance routes; it is refused (403) on the study's
signed-in routes (`/events`, `/ceremony/publish`).

### Trustee tokens (`--trustee-tokens`)

```json
[{"trustee_id": "1", "token_sha256": "<64 hex>"}, "... one per trustee"]
```

The file holds only the SHA-256 of each token. Make a token with
`saksi-campaign new-token` and its hash with `saksi-campaign hash-token <
token` (at least 32 bytes). A trustee process sends
`Authorization: Bearer <token>`; the console compares the hash against every
entry in constant time and acts as that trustee id only. Setting up an
election with `trustees: n` needs a token for each of `1..n`.

## Conventions

- JSON in, JSON out. Errors are `{"error": "<plain reason>"}`.
- A route's access is one of:
  - **public**: anyone.
  - **anonymous**: public, and the console drops the `Cookie` header before
    the handler runs, so the request is never linked to a session.
  - **admin**: a signed-in `admin` session (`POST /api/login`).
  - **voter**: a signed-in `voter` session; the route acts on that account.
  - **trustee token**: `Authorization: Bearer <token>`; the route acts as
    that token's trustee id only. A trustee's login session is not a token.
- Browser POSTs must be same-origin (the existing `guard`); a server-to-server
  call sends no `Origin` and passes.

| Status | Meaning |
|---|---|
| 200, 201 | done |
| 400 | malformed request, or an op refused the input (the op's own message) |
| 401 | no session / no valid trustee token |
| 403 | wrong role, or a trustee acting for another id |
| 404 | live mode off, or no live election set up |
| 409 | the election is in the wrong state for this, or the request conflicts with what is recorded |
| 413 | body too large |
| 422 | **the chaincode refused the transaction**: see below |
| 429 | rate limit (ballots) or too many open issuance sessions |
| 502 | the chain did not answer (not a refusal) |

A chaincode refusal (422) is:

```json
{"error": "SubmitBallot was refused by the chain", "refused": true,
 "gate": "nullifier",
 "reason": "submit SubmitBallot: rpc error: ... chaincode response 500, gate=nullifier: nullifier already spent in election \"...\" (double vote)"}
```

`reason` is the chain's text verbatim (the gateway's message and every
endorser's). `gate` is the chaincode's own `gate=<id>` when it names one
(`decode`, `shape`, `issuer`, `credential`, `election-exists`,
`election-open`, `nullifier`, `cds`, `selection`, `election-closed`,
`membership`, `cp-presence`, `partial-duplicate`, `dkg-duplicate`, ...).
`PublishTally`'s checks carry no gate id, so the console names them:
`threshold` (too few valid signatures, or none), `signature` (a signature
that does not verify, an unknown or repeated signer), `already-published`,
`election-closed`. Any other refusal is `refused`.

## States

```
setup -> ceremony -> open -> closed -> tallied -> verified
```

| State | Entered when | Allows |
|---|---|---|
| `setup` | `POST elections` made the keys and parameters | nothing; `CreateElection` is being recorded (a restart finishes it) |
| `ceremony` | `CreateElection` recorded | the key-ceremony routes |
| `open` | `PublishDKGTranscript` recorded | issuance, ballots, close |
| `closed` | `CloseElection` recorded | partials, tally signatures, `tally/publish` |
| `tallied` | `PublishTally` recorded | `verify` |
| `verified` | `verify-live` passed over the chain record | a new `POST elections` |

One live election at a time. A request in the wrong state gets 409 naming
the state.

## Admin

### `POST /api/live/elections` (admin; no election, or the last one verified)

```json
{"title": "Student council 2026",
 "positions": [{"id": "president", "candidates": ["alice", "bob", "carol"]},
               {"id": "secretary", "candidates": ["dan", "eve", "fay"]}],
 "trustees": 5, "threshold": 3}
```

`trustees` and `threshold` default to 5 and 3. Ids follow the wire format
(1-64 of `[A-Za-z0-9._-]`; contest ids at most 127 bytes). The console makes
the election id (`live-<utc yyyymmdd-hhmmss>-<8 hex>`, also the run id),
runs `issuer-keygen` (key file in the run's private folder) and
`election-params`, records `CreateElection`, and answers **201** with the
`GET /api/live/election` body (state `ceremony`).

Errors: 400 (title, counts, a trustee without a token, no voter accounts, or
`election-params` refused the positions), 409 (an election is running), 502
or 422 (the chain; the election stays in `setup` and the next console start
finishes it).

### `POST /api/live/close` (admin; open)

No body. Records `CloseElection`; answers the election view (state
`closed`). Issuance and ballots stop.

### `POST /api/live/tally/publish` (admin; closed)

No body. Publishes now with whatever trustee signatures exist: the largest
group of signatures over the same totals (with none, the totals `combine`
gives from the on-chain partials). It runs `tally-assemble` over the ballots
and partials read from the chain, which refuses totals the partials do not
decrypt to, and sends `PublishTally`. With fewer than `threshold` signatures
the chain refuses it: **422, gate `threshold`**, and **nothing changes**
(state, records and receipts are as before). On success:

```json
{"published": true, "totals": [2,1,0,0,1,2], "signatures_used": 3,
 "tx_id": "...", "block_number": 417}
```

409 if the partials on the chain do not combine yet.

### `POST /api/live/verify` (admin; tallied or verified)

No body. Reads the election back from the chain (parameters, transcript,
every ballot, every partial, the tally), runs `verify-live` with
`expected_ballots` the chain's nullifier count, stores the verdict as
`<run>/live-verify.json`, and moves to `verified` only when `overall` is
`pass`.

```json
{"state": "verified", "overall": "pass", "failed_checks": [],
 "expected_ballots": 6, "verdict": { "...": "the verify-live output" },
 "verified_at": "2026-11-14T08:00:00Z"}
```

A failed verdict answers 200 with `overall: "fail"` and the state stays
`tallied`. Read `overall` and `failed_checks`; the verdict's `summary` has 7
groups.

## Public

### `GET /api/live/election` (public)

Everything the phone's wasm needs, and the counts:

```json
{"run_id": "live-20261114-075259-1ced8307",
 "election_id": "live-20261114-075259-1ced8307",
 "title": "Student council 2026", "state": "open",
 "positions": [{"id": "president", "candidates": ["alice", "bob", "carol"]}, "..."],
 "trustees": 5, "threshold": 3,
 "params": "<hex ElectionParameters>",
 "contest_ids": ["president/alice", "..."],
 "issuer_public_key": "<point>",
 "dkg": "<hex DKGTranscript>",                 "(after the ceremony)"
 "joint_public_key": "<point>",
 "joint_key_fingerprint": "7A1B-...-E8F9",
 "verification_keys": [{"trustee_id": "1", "verification_key": "<point>", "fingerprint": "..."}],
 "roster_fingerprint": "3C4D-...",
 "ceremony_error": "...",                      "(only if the transcript was refused)"
 "counts": {"voters_on_roll": 3, "credentials_issued": 3,
            "ballot_records": 6, "ballot_records_source": "chain",
            "trustees_decrypted": 3, "tally_signatures": 3},
 "lifecycle": {"CreateElection": {"tx_id": "...", "block_number": 390}, "...": {}},
 "totals": [2,1,0,0,1,2],                     "(once tallied)"
 "verify_overall": "pass",
 "created_at": "...", "updated_at": "..."}
```

`ballot_records` is the chain's committed nullifier count
(`ballot_records_source: "chain"`), or the console's own count with
`"console"` when the chain did not answer. `trustees_decrypted` counts
trustees with a partial recorded for every contest. 404 before any setup.

### `GET /api/live/ledger` (public)

The election read back **from the chain**, not from the console's files.
Trustees, the verifier and anyone else aggregate from this.

```json
{"election_id": "...", "status": "open | closed | published",
 "params": "<hex>", "dkg": "<hex>", "tally": "<hex>",
 "nullifier_count": 6,
 "ballots": [{"nullifier": "<64 hex>", "position_id": "president",
              "tracking_code": "BC-7F3A-92C1",
              "ballot_fingerprint": "4F2A-...-7081",
              "ballot": "<hex Ballot exactly as the chain returns it>"}, "..."],
 "partials": [{"trustee_id": "1", "contest_id": "president/alice",
               "partial": "<hex PartialDecryption>"}, "..."]}
```

`ballot_fingerprint` is computed from the raw bytes `GetBallots` returned
(the wire format's definition), never from a re-marshalled record. Ballots are
in the chain's nullifier order. `partials` is read once the election is closed
(one `GetPartialDecryption` per contest and trustee). 502 if the chain does
not answer.

### `POST /api/live/ballot` (anonymous; open)

One position's ballot record, as the phone's `build_ballot` made it:

```json
{"ballot": "<hex Ballot: build_ballot().ballot>"}
```

The body is exactly this one field (an unknown field is 400), at most
256 KiB (413). The console checks only that the election is open (409) and the
string is hex (400), then submits **that exact string** with `SubmitBallot`.
It never decodes and re-encodes the record on its way to the chain; it decodes
a copy only to read the nullifier, reads the record back with `GetBallot`, and
fingerprints the bytes the chain returned.

```json
{"election_id": "...", "position_id": "president",
 "nullifier": "<64 hex>", "tracking_code": "BC-7F3A-92C1",
 "ballot_fingerprint": "4F2A-91C3-07B8-D6E5-1A2B-3C4D-5E6F-7081",
 "tx_id": "...", "block_number": 395,
 "recorded_bytes_match": true}
```

The phone compares `ballot_fingerprint` with the one it showed before cast.
`recorded_bytes_match` is false only if the read-back failed or differed (it
should never).

A refusal is 422 with the chain's reason verbatim and its gate: a replayed
ballot is `nullifier`, a record with one changed proof byte is `cds`, a
foreign credential is `issuer` or `credential`. The console does not
pre-check proofs, so the chain's own refusal is what the phone sees.

**Anonymity.** The handler reads no session (the `Cookie` header is removed
before it runs), no address and no other header. The run folder gets the
record, its `ballots.csv` row and its `SubmitBallot` receipt, and nothing that
names an account or an address. The rate limit is one global token bucket
(5 per second, burst 30; 429 with `Retry-After`), so no per-caller state is
kept either.

**No route accepts a challenged ballot or a Benaloh opening.** A challenged
ballot never leaves the phone before the fresh ballot is recorded
(`wire-format.md`, **The Benaloh challenge**); there is no server-side check.

## Voter

Sign in with `POST /api/login` (`{"username", "password"}`), then:

### `POST /api/live/issue/presign` (voter; open)

```json
{"blinded_commitment": "<point: begin_issuance().blinded_commitment>"}
```

```json
{"r": "<point>", "issuer_public_key": "<point>"}
```

Pass `r` and `issuer_public_key` to `blind_challenge`. A new presign for the
same account discards that account's earlier open session.

### `POST /api/live/issue/sign` (voter; open)

```json
{"e_prime": "<scalar: blind_challenge().e_prime>"}
```

```json
{"s_iss": "<scalar>", "issuer_public_key": "<point>"}
```

Exactly what `finalize_issuance` needs besides the phone's own state. The
console never receives the credential.

Rules (each tested):
- At most one signature per account per election, ever. The account is
  recorded in the run's private `issued.json` (atomically, fsynced) before
  `s_iss` is returned, and a restart keeps it. A second presign or sign for an
  issued account is 409; there is no reset route. A phone that loses its
  credential uses a spare account.
- At most one open session per account; a session lasts 10 minutes; at most 8
  are open at once (429). `sign` without an open session is 409.
- One `issue-presign` or `issue-sign` runs at a time across all accounts.
- Issuance is open only in state `open` (it ends with `close`).
- 403 for an account that is not a voter.

## Trustee (bearer token)

The key ceremony, in order. Every response is JSON; the `GET` routes can be
polled.

### `POST /api/live/dkg/receive-key` (trustee token; ceremony)

The `trustee-keygen` output: `{"trustee_id": 2, "receive_public_key":
"<point>", "fingerprint": "..."}` (`trustee_id`, if present, must be the
token's: else 403). Generate a fresh key per ceremony. A key may be replaced
until the roster is complete; then it is frozen (409). When the last key
arrives the console runs `dkg-roster`; a roster it refuses (a key twice) drops
the key just posted (409). Answers the roster status (below).

### `GET /api/live/dkg/roster` (trustee token)

```json
{"election_id": "...", "trustees": 5, "threshold": 3, "params": "<hex>",
 "complete": true, "received": [1,2,3,4,5],
 "peers": [{"trustee_id": 1, "receive_public_key": "<point>"}, "..."],
 "fingerprints": [{"trustee_id": 1, "receive_public_key": "<point>", "fingerprint": "..."}, "..."],
 "roster_digest": "<32-byte hex>", "roster_fingerprint": "3C4D-...",
 "dealt": [1,2], "acknowledged": []}
```

Before every key is in: `complete: false` and `received` only. `peers` is
`dkg-deal`'s roster input as it is; `roster_digest` is computed by
`dkg-roster`, exactly as `dkg-deal` and `dkg-receive` compute it. **A trustee
must still compare the digest with the other trustees' own hosts, never only
with this relay** (T4-1).

### `POST /api/live/dkg/deal` (trustee token; ceremony, roster complete)

The `dkg-deal` output as it is: `{"election_id", "dealer_id", "commitments",
"masked_shares", "roster_digest", "roster_fingerprint"}`. Checked: `dealer_id`
is the token's (403); the election; `roster_digest` is the published roster's
(409: the dealer saw a different roster); `threshold` commitments;
`masked_shares[k]` is from this dealer to `k + 1`, with 32-byte `nonce`,
`ciphertext` and `tag`. Each masked share is stored exactly as posted and
returned to its recipient unchanged; the console cannot unmask it. A deal is
made once (a different second deal is 409; the same one again is accepted).
Answers the roster status.

### `GET /api/live/dkg/inbox` (trustee token)

Until every trustee has dealt: `{"complete": false, "dealt": [...]}`. Then the
pieces of `dkg-receive`'s input for this trustee:

```json
{"election_id": "...", "trustee_id": 2, "complete": true, "dealt": [1,2,3,4,5],
 "params": "<hex>",
 "peers": [{"trustee_id": 1, "receive_public_key": "<point>"}, "..."],
 "roster_digest": "<32-byte hex>",
 "dealers": [{"dealer_id": 1, "receive_public_key": "<point>",
              "commitments": ["<point>", "..."],
              "masked_share": {"dealer_id": 1, "recipient_id": 2, "nonce": "...", "ciphertext": "...", "tag": "..."}},
             "... one per dealer, this trustee's own deal included"]}
```

Add `receive_key_file` and `share_file` and run `dkg-receive`.

### `POST /api/live/dkg/ack` (trustee token; ceremony, every deal in)

The `dkg-receive` output as it is (no secret in it): `{"election_id",
"trustee_id", "verification_key", "fingerprint", "joint_public_key",
"joint_key_fingerprint", "roster_digest", "roster_fingerprint"}`. Checked:
`trustee_id` is the token's (403), the roster digest (409). A different
second acknowledgement is 409.

When every trustee has acknowledged, the console runs `dkg-transcript` over
the dealers' commitments, checks that every trustee's `verification_key` and
`joint_public_key` equal the transcript's and that no key is the identity,
records `PublishDKGTranscript`, and opens the election:

```json
{"acknowledged": [1,2,3,4,5], "trustees": 5, "published": true,
 "joint_public_key": "<point>", "joint_key_fingerprint": "...",
 "transaction": {"tx_id": "...", "block_number": 391}}
```

Before the last: `{"acknowledged": [...], "trustees": 5, "published": false}`.
A mismatch is 409 naming the trustee (it was shown other commitments), the
election stays in `ceremony` with `ceremony_error` set, and nothing is
published. Each trustee then compares the published transcript on the chain
with its own keys (T4-2).

### `POST /api/live/partial` (trustee token; closed)

The `partial` output (only `partials` is read): `{"partials": [{"contest_id",
"partial"}, "..."]}`, computed over the ballots from `GET /api/live/ledger`.
Each partial must decode to a `PartialDecryption` of the token's trustee
(403 otherwise) for a contest of the election, each contest once. The console
records one `SubmitPartialDecryption` per contest (sent together) and answers:

```json
{"trustee_id": "2",
 "recorded": [{"contest_id": "president/alice", "tx_id": "...", "block_number": 400}, "..."],
 "trustees_decrypted": 2, "threshold": 3}
```

A contest already recorded for this trustee is answered from the record
without a second transaction, so a retry is safe. A chain refusal is 422
(e.g. `partial-duplicate`); the contests that went through stay recorded.
Read your partial back from `GET /api/live/ledger` and compare bytes (T4-4).
The console never decrypts and never runs `partial` or `sign-tally`.

### `POST /api/live/tally-sig` (trustee token; closed)

The `sign-tally` output (`totals` and `signature` are read; `trustee_id`, if
present, must be the token's): a signature over the totals this trustee
combined itself from the on-chain partials. The console checks it with
`tally-assemble` over the chain's ballots and partials (the totals must be
what the partials decrypt to, and the signature must verify) before keeping
it: 400 with the op's reason otherwise. One signature per trustee (a
different second one is 409).

When `threshold` signatures over the same totals are held, the console
publishes at once (as `tally/publish`):

```json
{"signatures": [1,2,3], "threshold": 3, "state": "tallied", "published": true,
 "totals": [2,1,0,0,1,2], "signatures_used": 3, "tx_id": "...", "block_number": 417}
```

Below threshold: `{"signatures": [1,2], "threshold": 3, "state": "closed",
"published": false}`. If the automatic publication was refused,
`publish_error` says why and the signature is still kept.

## The bulletin board on a live run

`GET /api/board/<run>` keeps its shape and every existing field's meaning.
For a live run (`mode: "live"`):

| Field | Live meaning |
|---|---|
| `mode` | `"live"` |
| `on_chain` | `true` |
| `status` | the live state |
| `sealed` | `true` until `tallied` |
| `verified` | the state is `verified` (verify-live passed over the chain record) |
| `contests` | the published totals, ranked, once tallied |
| `integrity.voters` | voter accounts; `ballot_records` the recorded ballots; `turnout_pct` ballot records over voters × positions |
| `crypto.trustees_submitted` | trustees with every contest's partial recorded; `threshold`, `trustees_total`, `issuer_public_key`, `committed_nullifiers` |
| `checks` | the ceremony, enough trustees decrypted, the tally on the chain, the verifier |
| `files` | `ballots.ndjson`, `receipts.csv`, `trail.ndjson` once tallied |

Added for live runs only, under `live`:

```json
{"live": {"state": "verified", "title": "...",
          "counts": {"voters_on_roll": 3, "credentials_issued": 3, "ballot_records": 6,
                     "ballot_records_source": "chain", "trustees_decrypted": 3, "tally_signatures": 3},
          "decryption": {"trustees_decrypted": 3, "threshold": 3, "trustees": 5,
                         "decrypted": [1,2,3], "tally_signatures": [1,2,3]},
          "joint_key_fingerprint": "...", "roster_fingerprint": "...",
          "ballots": [{"index": 0, "position_id": "president", "tracking_code": "BC-7F3A-92C1",
                       "ballot_fingerprint": "4F2A-...", "tx_id": "...", "block_number": 395}, "..."],
          "totals": [2,1,0,0,1,2], "contest_ids": ["president/alice", "..."],
          "verify_overall": "pass", "failed_checks": []}}
```

Each ballot's `ballot_fingerprint` is of the bytes the chain returned, next to
its tracking code. `GET /api/verify-code/<run>/<code>` works on a live run as
on a study run and adds `ballot_fingerprint` (live runs only).
`GET /api/board/<run>/files/<name>` serves the public files once tallied;
`live.json` and `private/` are never served.

## Run folder

`<runs>/<run id>/`:

| File | What | Public |
|---|---|---|
| `run.json` | run record, `config.mode: "live"` | no |
| `live.json` | the live state, rewritten atomically at every transition and recorded item; no secrets, no account names | no |
| `ballots.ndjson`, `ballots.csv` | each recorded ballot, as the chain returned it | yes, once tallied (`ballots.ndjson`) |
| `receipts.csv`, `trail.ndjson` | lifecycle and ballot receipts | yes, once tallied |
| `live-verify.json` | the last verify-live verdict | no |
| `private/` (0700) | `issuer.key`, `issued.json`, `sessions/` (all 0600) | never |

## Restart

A console restart loads the newest live election and reconciles with the
chain:
- `setup`: records `CreateElection` (an "already exists" answer counts as
  done);
- `ceremony` with every acknowledgement in: assembles and publishes the
  transcript (an existing transcript counts as done);
- `open` and the chain closed: `closed`;
- `closed` and a tally on the chain: `tallied`;
- in every state from `open`, ballots the chain holds but the run folder does
  not are appended (without a receipt; the tracking-code check then confirms
  them on the chain).

Issued accounts and open sessions are on disk, so issuance rules survive a
restart; sign-in sessions do not (log in again). If the chain is unreachable
at start the console still starts; every transition reads the chain before it
acts.
