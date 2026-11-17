# Live election HTTP API (`saksi-campaign serve --live`)

The console's routes for one live election: the presenter sets it up, the
trustee processes run the key ceremony and the decryption through it, the
phones check in, enrol and vote through it, and anyone reads the record back
from the chain. The voter list, the precinct check-in and the issuance gate
are specified in `voter-list-api.md`. The phone app (`apps/vote`) and the trustee process
(`saksi-campaign trustee --id N`, documented in `trustee-api.md`) are written
from this file.

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
    --web-dir /path/to/dist-web \
    --demo /path/to/saksi-demo \
    --fabric-tls-cert ... --fabric-cert ... --fabric-key ... \
    --live-precinct 0001A
```

- `--live-precinct` is the precinct number of the election's voter list
  (four digits and a capital letter; default `0001A`). See
  `voter-list-api.md`.

- `--tls-cert` and `--tls-key` together serve HTTPS (TLS 1.2 minimum). The
  session cookie is then `Secure`.
- `--live` refuses to start without `--auth-file`. Without TLS it starts only
  on a loopback `--addr` (`127.0.0.1`, `::1`, `localhost`) and prints a
  warning.
- `--live` needs `--trustee-tokens` (env `SAKSI_TRUSTEE_TOKENS`).
- On start the console loads the newest live election in `--runs` and resumes
  it from disk and the chain (see **Restart**).
- **`Host` must match the allowlist exactly, port included.** The console
  joins the `--addr` port to every `--allow-host` given without one, so the
  line above allows `vote.vancornelio.dev:8443` only. Browsers leave `:443`
  out of `Host`, so serving or forwarding the default port makes every
  request `403 forbidden host`. Phones use an explicit port in the URL:
  `https://vote.vancornelio.dev:8443/vote/`.

### The phone app (`/vote/`)

With `--web-dir <dir>` the console serves `<dir>/vote` at `/vote/` (static,
public, behind the same `guard` as every route; `/vote` redirects to
`/vote/`), next to `/board/`, `/trustee/` and `/admin/`. `.wasm` files are
served as `application/wasm`. **The phone page must be served from the
console's own origin:** the API sends no CORS headers, and `guard` refuses a
POST whose `Origin` is another origin. Building and copying the app into
`<dir>/vote` is not the console's job.

### Accounts (`--auth-file`)

The existing users file. The presenter is an `admin` account:

```json
[{"username": "ban", "role": "admin", "password_bcrypt": "$2a$12$..."}]
```

Hashes come from `saksi-campaign hash-password < password`. **Voters are not
accounts:** they are the rows of the precinct's voter list, uploaded at
setup, and a phone obtains its credential through the precinct check-in
(`voter-list-api.md`). A users file that still has `voter` accounts loads,
but such an account obtains nothing: it is refused on the issuance routes
(403 `no-checkin`) and on the study's signed-in routes (`/events`,
`/ceremony/publish`).

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

- JSON in, JSON out. Errors are `{"error": "<plain reason>"}`, with a
  stable `code` where one is listed (a ballot for another election, and
  every voter-list, check-in, desk and issuance refusal). Two
  answers come from `guard`, before any route, and are **plain text, not
  JSON**: `403 forbidden host` (a `Host` off the allowlist) and
  `403 cross-origin request rejected` (a POST whose `Origin` is another
  origin).
- A 500 carries one generic message; the detail is in the console's log
  only (issuance errors log a fixed description and no path).
- A route's access is one of:
  - **public**: anyone.
  - **anonymous**: public, and the console drops the `Cookie` header before
    the handler runs, so the request is never linked to a session.
  - **admin**: a signed-in `admin` session (`POST /api/login`).
  - **phone**: public by role; the route acts only on the check-in the
    phone's `saksi_checkin` cookie is bound to (`voter-list-api.md`).
  - **trustee token**: `Authorization: Bearer <token>`; the route acts as
    that token's trustee id only. A trustee's login session is not a token.
- Browser POSTs must be same-origin (the existing `guard`); a server-to-server
  call sends no `Origin` and passes.

| Status | Meaning |
|---|---|
| 200, 201 | done |
| 400 | malformed request, or an op refused the input (the op's own message); a ballot for another election (`code: "wrong-election"`) |
| 401 | no session / no valid trustee token |
| 403 | wrong role, a trustee acting for another id, or no check-in (`no-checkin`) |
| 404 | live mode off, or no live election set up |
| 409 | the election is in the wrong state for this, or the request conflicts with what is recorded (or with what the chain holds) |
| 413 | body too large |
| 422 | **the chaincode refused the transaction**: see below |
| 429 | rate limit (ballots and ledger reads; check-in finds per address) or too many open issuance sessions |
| 500 | an error inside the console (generic message; see the console log) |
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

Two refusals are answered from the chain instead of returned, because they
mean an earlier submit committed while the console lost its receipt: a
`partial-duplicate` (see `POST partial`) and an `already-published` tally
(see `POST tally/publish`).

## States

```
setup -> ceremony -> open -> closed -> tallied -> verified
  |         |
  +---------+--> abandoned   (POST abandon; terminal)
```

| State | Entered when | Allows |
|---|---|---|
| `setup` | `POST elections` made the keys and parameters | `POST elections` again (retries `CreateElection`), `abandon`; a restart also retries |
| `ceremony` | `CreateElection` recorded | the key-ceremony routes, `abandon` |
| `open` | `PublishDKGTranscript` recorded | check-in, issuance, ballots, close |
| `closed` | `CloseElection` recorded | partials, tally signatures, `tally/publish` |
| `tallied` | `PublishTally` recorded | `verify` |
| `verified` | `verify-live` passed over the chain record | `verify` again (a fail steps back to `tallied`), a new `POST elections` |
| `abandoned` | `POST abandon` in `setup` or `ceremony` | a new `POST elections`; nothing else. Never shown as tallied or verified |

One live election at a time. A request in the wrong state gets 409 naming
the state.

## Admin

### `POST /api/live/elections` (admin; no election, the last one verified or abandoned, or the current one in setup)

```json
{"title": "Student council 2026",
 "positions": [{"id": "president", "candidates": ["alice", "bob", "carol"]},
               {"id": "secretary", "candidates": ["dan", "eve", "fay"]}],
 "trustees": 5, "threshold": 3,
 "voter_list": "<the precinct's CSV text>",
 "voter_list_fingerprint": "<the preview's fingerprint>"}
```

`voter_list` and `voter_list_fingerprint` are required: the election is not
created unless the list is valid, non-empty and has the fingerprint the
presenter confirmed in `POST /api/live/voter-list/preview`. The list is then
locked. See `voter-list-api.md` for the file, the errors (400 with `code`
`voter-list-missing`, `voter-list-invalid`, `voter-list-unconfirmed`,
`voter-list-changed`) and the fingerprint. Body at most 192 KiB.

`trustees` and `threshold` default to 5 and 3. Ids follow the wire format
(1-64 of `[A-Za-z0-9._-]`; contest ids at most 127 bytes). The console makes
the election id (`live-<utc yyyymmdd-hhmmss>-<8 hex>`, also the run id),
runs `issuer-keygen` (key file in the run's private folder) and
`election-params`, records `CreateElection`, and answers **201** with the
`GET /api/live/election` body (state `ceremony`).

Errors: 400 (title, counts, a trustee without a token, the voter list, or
`election-params` refused the positions), 409 (an election is running past
setup), 502 or 422 (the chain; the election stays in `setup`).

**While the current election is in `setup`** (its `CreateElection` did not go
through), the same call retries that `CreateElection` instead of making a new
election: the body must still be a valid request, but its fields are not
used. It answers **200** with the election view (state `ceremony`), or the
chain's error again. A console restart retries it too.

### `POST /api/live/abandon` (admin; setup or ceremony)

No body. Gives up the current election before any credential or ballot
exists, so a stuck setup or ceremony (a transcript refused for a mismatched
acknowledgement, a trustee frozen out of the roster, a chain error at setup)
can be left without a fresh `--runs` folder. The run moves to the terminal
state `abandoned`, written atomically, and the answer is the election view.
Nothing is sent to the chain: the chain keeps its record of the election
(open, no transcript), which no ballot can use, since no credential was ever
issued under its issuer key. Then a new `POST elections` may start the next
election on the same `--runs` folder. A restart while abandoned stays
abandoned. The board shows an abandoned run with `status: "abandoned"`,
`sealed: true`, `verified: false`, and never its files. 409 in any other
state; 404 before any setup.

**Trustee processes** follow the election id in `GET /api/live/election` (or
the `state` in their roster and inbox polls): when the election they hold
keys for is abandoned and a new id appears, they start again with a fresh
receive key for the new election.

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

If the chain answers that a tally is already published (an earlier
`PublishTally` committed but the console lost its receipt), the console
reads the chain's tally: when it carries the totals the held signatures are
over, it is recorded, the state moves to `tallied`, and the answer is
`{"published": true, "already_on_chain": true, "totals": [...]}`; other
totals are 409 naming both.

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

A failed verdict answers 200 with `overall: "fail"` and the failed checks
recorded: the state stays `tallied`, or **steps back from `verified` to
`tallied`** on a failed re-verify, so the board never shows verified next to
a failed check. Read `overall` and `failed_checks`; the verdict's `summary`
has 7 groups.

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
 "precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
 "voter_list_fingerprint": "<64 hex>", "voter_list_fingerprint_short": "<16 hex>",
 "counts": {"voters_on_roll": 3, "voters_on_list": 3, "checked_in": 3, "credentials_issued": 3,
            "ballot_records": 6, "ballot_records_source": "chain",
            "trustees_decrypted": 3, "tally_signatures": 3, "trustees_joined": 5},
 "lifecycle": {"CreateElection": {"tx_id": "...", "block_number": 390}, "...": {}},
 "totals": [2,1,0,0,1,2],                     "(once tallied)"
 "verify_overall": "pass",
 "created_at": "...", "updated_at": "..."}
```

`voters_on_list` (and its older name `voters_on_roll`) is the number of
entries on the voter list; `checked_in` the entries that signed the list
(`voter-list-api.md`). `ballot_records` is the chain's committed nullifier count
(`ballot_records_source: "chain"`), or the console's own count with
`"console"` when the chain did not answer. The chain count is read at most once
every 2 seconds and shared by this view and the board, so a count shown can be
up to 2 seconds old (a failed read is reused for the same 2 seconds). `trustees_decrypted` counts
trustees with a partial recorded for every contest. `trustees_joined` counts
trustees whose receive key is in the key ceremony's roster: 0 after setup, the
trustee count once the roster is complete, and unchanged for the rest of the
election (it names no trustee). 404 before any setup.

This view, the board, the ledger read, the issuance gate and the ballot
route's state check read a snapshot of the public state that the console
republishes at every recorded change. They never wait for a transition in
progress, so a slow chain block during close or publish does not freeze them;
for that block wait they show the state from before the transition.

### `GET /api/live/ledger` (public)

The election read back **from the chain**, not from the console's files.
The verifier and anyone else can aggregate from this. The trustee processes do
not: each reads the chain through its own gateway connection
(`trustee-api.md`), because a console that relays the partials could show a
trustee a one-ballot view of the election.

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

Each read lists and fetches every ballot from the chain, so this route shares
the ballot route's token bucket (5 per second, burst 30): past it, 429 with
`Retry-After: 1`. A ledger read and a ballot each take one token.

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
256 KiB (413). The console checks only that the election is open (409), the
string is hex (400), and, when a copy of the record decodes, that it names
the live election: a ballot for another election is **400 with
`code: "wrong-election"`**, relayed nowhere and filed nowhere (the chaincode
files a ballot under the election named inside it, so without this check the
console would relay into any open election on the channel). A record that
does not decode is still relayed unchanged, so the chain's `decode` gate
answers it. Then the console submits **that exact string** with
`SubmitBallot`. It never decodes and re-encodes the record on its way to the
chain; it decodes a copy only for the election check and the nullifier, reads
the record back with `GetBallot`, and fingerprints the bytes the chain
returned.

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

**Same origin, no cookie.** The phone POSTs from the page the console served
at `/vote/`, with `fetch(..., {credentials: "omit"})`: its `Origin` equals
`Host`, so `guard` passes it, and no cookie is sent (the console would drop it
anyway).

**Anonymity.** The handler reads no session (the `Cookie` header is removed
before it runs), no address and no other header. The run folder gets the
record, its `ballots.csv` row and its `SubmitBallot` receipt, and nothing that
names a voter, an account or an address. The rate limit is one global token bucket
(5 per second, burst 30; 429 with `Retry-After`), shared with
`GET /api/live/ledger`, so no per-caller state is kept either.

**No route accepts a challenged ballot or a Benaloh opening.** A challenged
ballot never leaves the phone before the fresh ballot is recorded
(`wire-format.md`, **The Benaloh challenge**); there is no server-side check.

## Phone: check-in and issuance

The phone checks in first (`POST /api/live/checkin/find`, `declare`, the
presenter's approval, `checkin/sign`; all in `voter-list-api.md`). The
`saksi_checkin` cookie `declare` sets is then the phone's only standing for
issuance: no sign-in, and no account of any role.

### `POST /api/live/issue/presign` (phone; open; check-in `signed`)

```json
{"blinded_commitment": "<point: begin_issuance().blinded_commitment>"}
```

```json
{"r": "<point>", "issuer_public_key": "<point>"}
```

Pass `r` and `issuer_public_key` to `blind_challenge`. A new presign for the
same list entry discards that entry's earlier open session.

### `POST /api/live/issue/sign` (phone; open; check-in `signed`)

```json
{"e_prime": "<scalar: blind_challenge().e_prime>"}
```

```json
{"s_iss": "<scalar>", "issuer_public_key": "<point>"}
```

Exactly what `finalize_issuance` needs besides the phone's own state. The
console never receives the credential.

**Never retry `sign`, and never run two issuances for one check-in at once.**
The entry is recorded as `credential_issued` before `s_iss` is sent. If that
response is lost (a dropped connection, a closed tab), or a second tab's
presign replaces the first tab's session, the entry is spent with no
credential: a retried `sign` is 409 `already-issued`, and there is no reset
and no replacement. The console keeps no copy of `e_prime` or `s_iss` to
answer a retry with.

Rules (each tested):
- Only for a check-in in state `signed` (403 `no-checkin` without one, or for
  one the Board ended; 409 `not-signed` at the desk or approved).
- At most one signature per list entry per election, ever. The entry moves
  to `credential_issued` in the run's private `checkin.json` (atomically,
  fsynced) before `s_iss` is returned, and a restart keeps it. The record
  holds **no time**: the ballots are public in arrival order with their
  commit times, so an issuance time per entry would help link entries to
  ballots. An issuance does not move `updated_at` either. If the record
  cannot be written, the signature is withheld (500) and the entry may start
  again. A second presign or sign for an issued entry is 409
  `already-issued`; the desk cannot reset it.
- At most one open session per entry; a session lasts 10 minutes; at most 8
  are open at once (429). `sign` without an open session is 409. A desk
  reset removes the entry's open session.
- One `issue-presign` or `issue-sign` runs at a time across all entries.
- Issuance is open only in state `open` (it ends with `close`).

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
{"election_id": "...", "state": "ceremony", "trustees": 5, "threshold": 3, "params": "<hex>",
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
with this relay** (T4-1): the trustee processes do, through each other's
`GET /api/trustee/peer`.

### `POST /api/live/dkg/deal` (trustee token; ceremony, roster complete)

The `dkg-deal` output as it is: `{"election_id", "dealer_id", "commitments",
"masked_shares", "roster_digest", "roster_fingerprint"}`. Checked: `dealer_id`
is the token's (403); the election; `roster_digest` is the published roster's
(409: the dealer saw a different roster); `threshold` commitments;
`masked_shares[k]` is from this dealer to `k + 1`, with 32-byte `nonce`,
`ciphertext` and `tag`. Each masked share is stored as posted and returned
to its recipient with an **unchanged JSON value** (the same fields and
values; JSON whitespace may differ, since it is kept inside `live.json`); the
console cannot unmask it, and its AEAD tag is what protects its integrity. A deal is
made once (a different second deal is 409; the same one again is accepted).
Answers the roster status.

### `GET /api/live/dkg/inbox` (trustee token)

Until every trustee has dealt: `{"election_id", "state", "trustee_id",
"complete": false, "dealt": [...]}`. Then the pieces of `dkg-receive`'s input
for this trustee:

```json
{"election_id": "...", "state": "ceremony", "trustee_id": 2, "complete": true, "dealt": [1,2,3,4,5],
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
with its own keys (T4-2). Such an election cannot finish: `POST abandon` it
and start the next one.

### `POST /api/live/partial` (trustee token; closed)

The `partial` output (only `partials` is read): `{"partials": [{"contest_id",
"partial"}, "..."]}`, computed over every ballot record on the chain (the
trustee process reads them itself; `trustee-api.md`).
Each partial must decode to a `PartialDecryption` of the token's trustee
(403 otherwise) for a contest of the election, each contest once. The console
records one `SubmitPartialDecryption` per contest (sent together) and answers:

```json
{"trustee_id": "2",
 "recorded": [{"contest_id": "president/alice", "tx_id": "...", "block_number": 400,
               "already_on_chain": false}, "..."],
 "trustees_decrypted": 2, "threshold": 3}
```

A contest already recorded for this trustee is answered from the record
without a second transaction, so a retry is safe. If the chain refuses a
contest as `partial-duplicate` (an earlier submit committed but the console
lost its receipt), the console reads the chain's partial for that trustee
and contest: **byte-equal** to the one posted, it is recorded and answered
200 with `already_on_chain: true` (and no `tx_id`); **different**, it is 409
naming the trustee and contest. Any other chain refusal is 422; the contests
that went through stay recorded. On a restart from `closed` onward the
console also fills its record from the partials on the chain.
Read your partial back from the chain (`GetPartialDecryption`) and compare
bytes (T4-4).
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
| `status` | the live state (`abandoned` included) |
| `sealed` | `true` until `tallied` (an abandoned run stays sealed) |
| `verified` | the state is `verified` (verify-live passed over the chain record) |
| `contests` | the published totals, ranked, once tallied |
| `integrity.voters` | entries on the voter list; `ballot_records` the recorded ballots; `turnout_pct` ballot records over voters × positions |
| `crypto.trustees_submitted` | trustees with every contest's partial recorded; `threshold`, `trustees_total`, `issuer_public_key`, `committed_nullifiers` (the chain count, up to 2 seconds old, as in the election view) |
| `checks` | the ceremony, enough trustees decrypted, the tally on the chain, the verifier |
| `files` | `ballots.ndjson`, `receipts.csv`, `trail.ndjson` once tallied |

Added for live runs only, under `live`:

```json
{"live": {"state": "verified", "title": "...",
          "precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
          "voter_list_fingerprint": "<64 hex>", "voter_list_fingerprint_short": "<16 hex>",
          "voter_list_note": "The list is kept by the election console. It is not written to the ledger.",
          "counts": {"voters_on_roll": 3, "voters_on_list": 3, "checked_in": 3, "credentials_issued": 3, "ballot_records": 6,
                     "ballot_records_source": "chain", "trustees_decrypted": 3, "tally_signatures": 3,
                     "trustees_joined": 5},
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
| `live.json` | the live state, rewritten atomically at every transition and recorded item; no secrets, no voter names (the precinct, the list fingerprint and count only) | no |
| `ballots.ndjson`, `ballots.csv` | each recorded ballot, as the chain returned it; a ballot's line and row are written together or not at all (a failed write cuts both back) | yes, once tallied (`ballots.ndjson`) |
| `receipts.csv`, `trail.ndjson` | lifecycle and ballot receipts | yes, once tallied |
| `live-verify.json` | the last verify-live verdict | no |
| `private/` (0700) | `issuer.key`, `voter-list.json` (the locked list, with dates of birth), `checkin.json` (each entry's check-in state, token hash and signature; no times), `sessions/` (all 0600) | never |

## Restart

A console restart loads the newest live election and reconciles with the
chain:
- `setup`: records `CreateElection` (an "already exists" answer counts as
  done);
- `ceremony` with every acknowledgement in: assembles and publishes the
  transcript (an existing transcript counts as done);
- `open` and the chain closed: `closed`;
- `closed` and a tally on the chain: `tallied`;
- in every state from `closed`, partials the chain holds but `live.json` does
  not are recorded (without a transaction id);
- in every state from `open`, ballots the chain holds but the run folder does
  not are appended (without a receipt; the tracking-code check then confirms
  them on the chain);
- `abandoned`: nothing; it stays abandoned.

The voter list, every check-in (with the phones' cookies), the issued
entries and the open sessions are on disk, so check-in and issuance rules
survive a restart; sign-in sessions do not (log in again). An election made
before voter lists existed loads, but its check-in, desk and issuance routes
answer 409 `no-voter-list`. If the chain is unreachable
at start the console still starts and logs the failure; nothing reconciles
until the next restart. The transitions themselves do not re-read the chain
first: a setup retry and `close` submit directly and take an "already
exists" or "already closed" answer as done; the ceremony's last
acknowledgement takes "already published" (`dkg-duplicate`) as done; a
partial or a tally already on the chain is answered as above.
