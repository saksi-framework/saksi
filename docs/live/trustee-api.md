# Live election trustee process (`saksi-campaign trustee`)

One process per trustee. Each holds that trustee's secrets (its receive key and
its key share) in its own private folder, runs that trustee's
`saksi-demo live` ops (`wire-format.md`, section **Trustee**), reads the ledger
itself through its own Fabric gateway connection, and talks to the console
(`http-api.md`) only to post what the trustee produced. The trustee app
(`apps/trustee`, task 6) is built from this file: it is served by the process
at `/trustee/` and calls the routes below on the same origin.

This is a later build, not the study build. The study's routes are unchanged.

## What the process trusts the console for

Nothing it acts on. The console relays the trustees' partial decryptions, so a
console that showed a trustee a one-ballot view of the election could open
that one vote. So:

- **Read from the chain, never from the console:** the election as created
  (`GetElection`), its status (`GetElectionStatus`), the DKG transcript
  (`GetDKGTranscript`), every ballot (`ListNullifiers`, paged, then
  `GetBallots`), this trustee's own partial (read back), every trustee's
  partials for the combine (`GetPartialDecryption`), and the published tally
  (`GetTally`). There is no fallback to the console's view: if the chain cannot
  be read, the step fails with a message saying so, and the trustee presses
  again to retry.
- **From the console only:** which election id is current, and its state, for
  display (`GET /api/live/election`). The parameters it states are checked
  against the chain before anything is dealt.
- **The roster is checked with the other trustees' own hosts**, not only with
  the console (each process serves `GET /api/trustee/peer`).
- **Only writes go through the console:** the receive key, the deal, the
  acknowledgement, the partial decryption and the tally signature, each posted
  exactly as the CLI printed it.

## Starting it

```
saksi-campaign trustee --id 2 \
    --addr 0.0.0.0:9002 --tls-cert fullchain.pem --tls-key privkey.pem \
    --allow-host t2.vancornelio.dev \
    --auth-file trustee2-accounts.json \
    --console https://vote.vancornelio.dev:8443 \
    --token-file trustee2.token \
    --state-dir ~/.saksi/live-trustee-2 \
    --peers 1=https://t1.vancornelio.dev:9001,3=https://t3.vancornelio.dev:9003,4=https://t4.vancornelio.dev:9004,5=https://t5.vancornelio.dev:9005 \
    --demo /path/to/saksi-demo --web-dir /path/to/dist-web \
    --fabric-tls-cert .../peers/peer0.org1.example.com/tls/ca.crt \
    --fabric-cert .../users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem \
    --fabric-key .../users/User1@org1.example.com/msp/keystore/priv_sk
```

| Flag | Default | Meaning |
|---|---|---|
| `--id N` | required | This trustee's id, `1..n`. |
| `--addr` | `127.0.0.1:9001` | Bind address. |
| `--tls-cert`, `--tls-key` | none | Serve HTTPS (TLS 1.2 or later). Given together or not at all. **Without them the process starts only on a loopback `--addr`** and prints a warning. |
| `--allow-host` | none | Accepted `Host` header, repeatable. A host without a port gets `--addr`'s port, so `t2.vancornelio.dev` with `--addr 0.0.0.0:9002` allows `t2.vancornelio.dev:9002`. Loopback names are always allowed. |
| `--auth-file` | required | This process's own accounts file (the users-file format of `http-api.md`): **only trustee accounts with this `--id`**. Any other account (an admin, a voter, another trustee) refuses the start. |
| `--console` | required | The console's base URL, `https://<host>:<port>`. **The host and port must be in the console's `--allow-host` list, and the name must be on the console's certificate**: `https://localhost:8443` against a `vote.vancornelio.dev` certificate fails. TLS is verified against the system roots. |
| `--console-ca` | none | An extra CA certificate (PEM) trusted for the console and the peers, besides the system roots. For tests. Nothing turns verification off. |
| `--token-file` | required | This trustee's bearer token for the console (`saksi-campaign new-token`; the console holds its hash). The file must be mode `0600` (nothing for group or others), or the process refuses to start. |
| `--state-dir` | required | This trustee's private folder (below). Created `0700`; an existing folder that grants anything to group or others refuses the start. |
| `--peers` | none | The other trustees' base URLs by id, `id=https://host:port`, comma-separated. Its own id may be listed and is ignored. Each must be `https`. A roster id with no URL here is waited for. |
| `--demo` | `saksi-demo` | The `saksi-demo` binary. |
| `--web-dir` | none | Serve the trustee app at `/trustee/` from `<dir>/trustee`. |
| `--min-ballots` | `2` | Refuse to decrypt a position with fewer ballot records. A one-ballot aggregate is that voter's choice, so `1` is for rehearsals only. |
| `--fabric-peer` | `localhost:7051` | The Fabric gateway peer this trustee reads the ledger from. |
| `--fabric-gateway-peer` | `peer0.org1.example.com` | The peer's TLS server name. |
| `--fabric-tls-cert`, `--fabric-cert`, `--fabric-key` | required | The peer's TLS CA and the reading identity's certificate and key. The key is read in place. |
| `--fabric-msp-id` | `Org1MSP` | The reading identity's MSP. |
| `--fabric-channel`, `--fabric-chaincode` | `saksi`, `saksi-bulletin` | |

At start the process:
1. checks the TLS rule, the token file's mode, the state folder's mode, the
   accounts file and the Fabric flags;
2. calls `GET /api/live/election` on the console. A certificate that does not
   verify or name the host, or a `403 forbidden host` from the console's guard,
   stops it with a message naming the allowlist and the certificate;
3. asks the console which trustee the token is (`GET /api/live/dkg/inbox`
   answers the token's `trustee_id`). A token the console does not accept
   (401), or one that is another trustee's, stops it. With no election set up
   the console cannot say yet; the check then runs when an election appears,
   and nothing is done until it passes.

## State folder

```
<state-dir>/                         0700
  current.json                       0600  {"election_id": "..."}: the election last followed
  elections/                         0700
    <election id>/                   0700  one folder per election, never reused
      receive.key                    0600  this election's receive key (trustee-keygen; secret)
      share.json                     0600  this trustee's key share (dkg-receive; secret)
      progress.json                  0600  where this trustee stands (public values only)
```

- **A fresh receive key per election id.** A key is never reused across
  elections; a new election id gets a new folder. When the console's election
  changes (an abandoned ceremony and a new election), the old folder is left
  exactly as it was.
- **Secret files** are written by the CLI (`O_EXCL`, `0600`) to
  `<name>.new`; their public half (the receive public key, or the
  `dkg-receive` output) is saved in `progress.json`; only then is the file
  renamed into place. After a kill, a `.new` file whose public half was saved
  is renamed, and one whose public half was not (it was never used) is
  removed.
- **`progress.json`** is rewritten atomically (temporary file, fsync, rename)
  after every step. It holds the button presses, the chain's parameters, the
  receive public key, the roster and its digest, the peers' check results,
  this trustee's own deal and acknowledgement (as the CLI printed them), the
  transcript check, the ballot set's digest and counts, this trustee's partial
  (as printed), its combine, its signature (as printed), the published tally,
  the steps' states and the alarms. No secret.
- **Nothing secret leaves the process:** no share, receive key, token or
  Fabric key is in any response, log line, error string or status. Only
  fingerprints and public keys.

## The three buttons

Each button starts a background step and answers at once. The step survives a
page reload and a process restart: the press is recorded in `progress.json`,
and after a restart the process works out where it is from that record and the
chain, and continues. `GET /api/trustee/status` always says where things
stand.

### Join ceremony (console state `ceremony`)

1. **Parameters.** Reads the election from the chain and checks it equals the
   `params` the console states, that its trustee ids are `"1".."n"`, and that
   `n`, `t` and the election id are the ones the console states. Otherwise
   alarm `params`.
2. **Receive key.** Makes a fresh receive key for this election id
   (`trustee-keygen`), or reuses the one in this election's folder.
3. **Posts the receive key** (`POST /api/live/dkg/receive-key`). After a
   restart it posts the same key again; once the roster is frozen a different
   key is refused by the console, and only an abandon gets past that.
4. **Roster.** Polls `GET /api/live/dkg/roster` until it is complete. Checks the
   roster's `params` are the chain's, that its own entry is its own key
   (alarm `roster-own-key`), computes the roster digest itself (`dkg-roster`)
   and checks it equals the console's (alarm `roster-digest`).
5. **Checks the roster with every other trustee's own host** before dealing:
   fetches `GET /api/trustee/peer` from each peer. The receive key the peer
   states for itself must be the roster's key for that peer, and the peer's
   own roster digest (all 32 bytes) must equal this trustee's. A mismatch is
   alarm `roster-peer-<id>`, naming the peer and what differed; a peer stating
   another key is shown before a digest difference. **A peer that is not
   reachable, is on another election, or has no digest yet is waited for, not
   skipped.**
6. **Deals** (`dkg-deal` over the chain's parameters and the checked roster;
   its digest must be the checked one) and posts the output exactly as printed
   (`POST /api/live/dkg/deal`). The output is saved before it is posted, so a
   retry posts the same deal.
7. **Receives.** Polls `GET /api/live/dkg/inbox` until every deal is in. Checks
   the inbox is for this trustee, the chain's parameters and the checked
   roster, and that its own deal's commitments are the ones it dealt (alarm
   `inbox`, `inbox-own-deal`). Runs `dkg-receive`, which verifies every share
   against its dealer's commitments and the roster (a failure is alarm
   `receive`, naming the dealer), and posts the output exactly as printed
   (`POST /api/live/dkg/ack`).
8. **Transcript.** When the console reports the election open, reads the
   transcript **from the chain** and checks: this trustee's own commitments
   are under its id; the transcript is exactly `dkg-transcript` of the
   commitments it carries; its joint key is the one this trustee derived; its
   verification key for this trustee is this trustee's key share. A mismatch
   is alarm `transcript`, which blocks Decrypt and Sign for this election.
   If the console refused to publish (`ceremony_error`), the step fails with
   that message.
9. Shows the share fingerprint and the joint key fingerprint (128 bits,
   `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, as `wire-format.md` says).

The join step is `done` once the transcript on the chain is checked.

### Decrypt (chain status `closed`)

1. **The press is refused at once (409)** unless the transcript was checked and
   the chain says the election is `closed`. A chain that cannot be read gives
   502.
2. Reads every ballot from the chain: every page of `ListNullifiers`, then
   `GetBallots`, then `ListNullifiers` again. **The number of records must equal
   the chain's nullifier count**, before and after; otherwise the step fails.
3. Runs `aggregate` over them for the ballot set's fields: `ballot_count`,
   `ballots_by_position` and **`ballots_digest`**, the wire format's
   order-independent digest:
   `SHA-256("saksi.live.ballot-set.v1" || u64be(len id) || id || u64be(count) || sorted SHA-256(record bytes)...)`.
   Its first 16 bytes are `ballots_fingerprint`.
4. **Once per election.** If this trustee already recorded a ballot set for
   this election and the chain now gives another, the step is refused. A retry
   over the same set re-posts the same partial (the console answers an
   already-recorded partial as success).
5. **`--min-ballots`.** A position with fewer records is refused (default 2).
6. Compares `ballots_digest` with every other trustee that has one for this
   election (from its peer page). A difference is alarm `ballots-peer-<id>`.
   A peer that has none yet is listed and not waited for, since each trustee
   reads the set from the chain itself.
7. Runs `partial` over the chain's ballots with its own share (the output's
   digest must be the recorded one), saves it, and posts it exactly as printed
   (`POST /api/live/partial`). A 409 saying the chain holds a different partial
   under this trustee's id is alarm `partial-conflict`.
8. **Reads its partial back from the chain**, contest by contest, and compares
   bytes. A difference is alarm `partial-readback`.

### Combine (automatic) and Sign tally

- **Combine** runs by itself once the console counts at least `threshold`
  trustees decrypted (or the tally is published): it reads the ballots, every
  trustee's partials from the chain and checks at least `threshold` trustees
  have a partial for every contest, then runs `combine` with its own aggregate.
  The ballot set must be the one this trustee decrypted, if it did (alarm
  `ballots-changed`); a trustee that did not decrypt records the set here. The
  totals are shown **before anything is signed** (`tally.totals`,
  `tally.ready_to_sign`).
- **Sign tally** (the press) carries the totals shown:
  `{"totals": [2,1,0,0,1,2]}`. They must equal this trustee's own combine (409
  otherwise). The process runs `sign-tally` over the same ballots and partials,
  saves the signature, and posts it (`POST /api/live/tally-sig`). **A 400 means
  the console's totals differ from this trustee's**: alarm `tally-totals`. If
  the tally was already published with other trustees' signatures, the step
  ends `done` with `signature_note` saying so.
- **Published.** When the console reports the election tallied, the process
  reads the tally from the chain and shows whether it equals its own combine
  (`tally.matches`); a difference is alarm `tally-differs`.

### Other rules

- **Following the election.** The process polls `GET /api/live/election`. When
  the id changes, it starts clean for the new id in a new folder; the old one
  is left as it is. If the trustee had pressed Join and the old ceremony did
  not finish (it was abandoned), the new election's Join starts by itself with
  a fresh receive key. In state `abandoned` every unfinished step fails with a
  message saying so.
- **Token and id.** The token acts only as its own trustee on the console. The
  process checks, through the console's inbox answer, that its token is its
  `--id`'s, at start and for every new election; until it is, nothing runs and
  `identity` says why.
- **The console is slow, not refusing.** A console call may wait up to about
  2.5 minutes on the console's state lock while it submits to a stalled chain;
  the process's timeout is 4 minutes, and a timeout, a transport error or a
  502/503/504 is shown as `waiting` and tried again by itself.

## Local HTTP API

Same origin as the app (`/trustee/`). JSON in, JSON out; errors are
`{"error": "<plain reason>"}`. Every route passes the Host allowlist and the
same-origin POST check (`guard`), which answer **plain text**
`403 forbidden host` and `403 cross-origin request rejected`. Every route is in
the process's access table; an unknown path is 404.

| Route | Method | Access |
|---|---|---|
| `/api/login` | POST | public |
| `/api/logout` | POST | public |
| `/api/me` | GET | public (401 without a session) |
| `/api/trustee/status` | GET | this trustee's session |
| `/api/trustee/join` | POST | this trustee's session |
| `/api/trustee/decrypt` | POST | this trustee's session |
| `/api/trustee/sign` | POST | this trustee's session |
| `/api/trustee/peer` | GET | public (the other trustees) |
| `/trustee/` | GET | public (the app's static files, with `--web-dir`) |

"This trustee's session" is a session of an account in `--auth-file`, all of
which are trustee accounts with this `--id`. A session of the console, or of
another trustee's process, means nothing here (each process has its own
sessions in memory, and its own host, so its own cookie). Without a session:
401; any other account: 403.

### `POST /api/login`, `POST /api/logout`, `GET /api/me`

The shapes the trustee app already uses (the console's auth code):
- login: `{"username", "password"}` → **204** and a session cookie
  `saksi_session` (`HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` over
  HTTPS, no `Domain`, so only this host gets it). 401 bad credentials, 429
  after repeated failures (`Retry-After`).
- logout: **204**, the cookie cleared.
- me: `{"username": "trustee2", "role": "trustee", "trustee_id": "2"}`, or 401.

Sessions live in memory: a process restart signs the trustee out (the steps
carry on).

### `GET /api/trustee/status`

Everything a screen needs, in one read. Poll it (every 1 to 2 seconds).

```json
{
  "trustee_id": 2,
  "console": {"url": "https://vote.vancornelio.dev:8443", "reachable": true, "error": ""},
  "identity": {"checked": true, "ok": true},
  "election": {
    "election_id": "live-20261114-122055-7c929547", "title": "Student council 2026",
    "state": "closed", "trustees": 5, "threshold": 3,
    "positions": [{"id": "president", "candidates": ["alice", "bob", "carol"]}, "..."],
    "contest_ids": ["president/alice", "..."],
    "params_checked": true, "ballot_records": 6
  },
  "step": "decrypt",
  "steps": {
    "join":    {"state": "done", "updated_at": "..."},
    "decrypt": {"state": "running", "detail": "", "error": "", "updated_at": "..."},
    "sign":    {"state": "idle"}
  },
  "alarms": [],
  "fingerprints": {
    "receive_key": "5E6F-...", "roster": "3C4D-...", "share": "1A2B-...",
    "joint_key": "7A1B-...", "ballots": "9C1D-..."
  },
  "ceremony": {
    "receive_key_posted": true, "roster_complete": true, "roster_digest": "<64 hex>",
    "roster": [
      {"trustee_id": 1, "receive_key_fingerprint": "...", "self": false, "peer_check": "ok"},
      {"trustee_id": 2, "receive_key_fingerprint": "...", "self": true,  "peer_check": "self"},
      {"trustee_id": 3, "receive_key_fingerprint": "...", "self": false, "peer_check": "waiting",
       "detail": "not reachable: ..."}
    ],
    "roster_checked": true, "dealt": true, "received": true, "acknowledged": true,
    "joint_public_key": "<point>", "verification_key": "<point>",
    "transcript_published": true, "transcript_check": "ok", "ceremony_error": ""
  },
  "decryption": {
    "min_ballots": 2, "ballot_count": 6,
    "ballots_by_position": {"president": 3, "secretary": 3},
    "ballots_digest": "<64 hex>",
    "peer_checks": [{"trustee_id": 1, "state": "ok"}, {"trustee_id": 3, "state": "waiting", "detail": "..."}],
    "partial_computed": true, "partial_recorded": true, "partial_read_back": "ok",
    "trustees_decrypted": 2, "threshold": 3
  },
  "tally": {
    "totals": [2,1,0,0,1,2],
    "contests": [{"contest_id": "president/alice", "total": 2}, "..."],
    "ready_to_sign": true, "signature_posted": false, "signature_note": "",
    "published": false, "published_totals": [], "matches": null
  },
  "updated_at": "..."
}
```

Fields:

| Field | Values |
|---|---|
| `console.reachable` | false while the last console call failed; `console.error` says why. |
| `identity` | `checked: false` until an election exists; `ok: false` with `error` when the token is not this `--id`'s or the console refuses it. Nothing runs until `ok`. |
| `election` | `null` before the console has an election. `state` is the console's (`setup`, `ceremony`, `open`, `closed`, `tallied`, `verified`, `abandoned`), for display. `params_checked`: the parameters were checked against the chain. `ballot_records`: the console's count of the chain's records. |
| `step` | The step in progress: the first of `join`, `decrypt`, `sign` that is `running`, else the first `waiting`; `""` when none. |
| `steps.<step>.state` | `idle` (not pressed), `running`, `waiting` (on someone else; `detail` says on what; it carries on by itself), `done`, `failed` (`error` says why; **press the button again to retry**, for example after a chain read failure), `refused` (`error` says why: not closed, under `--min-ballots`, another ballot set, the ceremony was over before this trustee joined), `blocked` (an alarm blocks it for this election). |
| `steps.sign` before the press | `waiting` with `detail` "...press Sign tally..." once the combine is ready; `waiting` with `detail` or `error` while the combine waits for partials or cannot read the chain. |
| `alarms[]` | `{code, message, blocks, at}`: see below. Shown until the election changes. |
| `fingerprints` | 128-bit fingerprints of this trustee's receive key, the roster digest, its key share, the joint key and the ballot set. Compare them aloud with the other trustee pages, the board and the phones. |
| `ceremony.roster[].peer_check` | `self`; `pending` (not checked yet); `ok`; `waiting` (with `detail`); `mismatch` (with `detail`, and an alarm). |
| `ceremony.transcript_check` | `""` (not yet), `ok`, `mismatch`. |
| `decryption.peer_checks[].state` | `ok`, `waiting` (the peer has no set yet, or is unreachable; not waited for), `mismatch`. |
| `decryption.partial_read_back` | `""`, `ok`, `mismatch`. |
| `tally.totals` | This trustee's own combine, in `contest_ids` order; `[]` until it ran. |
| `tally.ready_to_sign` | Totals are shown, Sign was not pressed, nothing blocks it. |
| `tally.matches` | `null` until both the published tally and this trustee's combine are known; then whether they are equal. |

### `POST /api/trustee/join`, `POST /api/trustee/decrypt`

No body (an empty JSON object is accepted). **202** with the status body: the
step has started (or carries on, or is done already). A step that `failed` or
was `refused` starts again. Refusals, before anything starts:
- **409** no election yet; a blocking alarm (`blocked by an alarm: ...`); the
  token is not this trustee's; join after the ceremony is over; decrypt before
  the transcript was checked; **decrypt while the chain does not say
  `closed`** (`the chain says the election is open, not closed`);
- **502** decrypt, when the chain status cannot be read.

### `POST /api/trustee/sign`

```json
{"totals": [2,1,0,0,1,2]}
```

The totals the screen showed (`tally.totals`). **202** with the status body.
**409** when there are no totals yet, when they differ from this trustee's own
combine, or when an alarm blocks signing. Nothing is ever signed without this
press.

### `GET /api/trustee/peer` (public)

What this trustee states for itself about the current election, for the other
trustees to compare. Nothing secret, and nothing that is not already, or soon,
public.

```json
{"trustee_id": 2, "election_id": "live-...",
 "receive_public_key": "<point>", "receive_key_fingerprint": "...",
 "roster_digest": "<64 hex>", "roster_fingerprint": "...",
 "ballots_digest": "<64 hex>", "ballots_fingerprint": "..."}
```

Each field is present once known: the receive key once posted, the roster
digest once this trustee computed it, the ballot set once it read it.

## Alarms

An alarm is something a check caught. It is shown in `alarms` with the steps it
blocks, and a blocked button answers 409. It stays until the election changes;
the way past one is the presenter abandoning the ceremony (before voting) or
investigating.

| Code | Raised when | Blocks |
|---|---|---|
| `params` | The console's parameters differ from the chain's, or the chain's are unusable for this trustee | join, decrypt, sign |
| `roster-params`, `roster`, `roster-own-key`, `roster-digest` | The roster names other parameters, has the wrong size, holds another key for this trustee, or its digest differs from the one this trustee computes | join, decrypt, sign |
| `roster-peer-<id>` | Peer `<id>`'s own host states another receive key than the roster, says it is another trustee, or computed another roster digest | join, decrypt, sign |
| `deal-roster` | `dkg-deal` computed another digest than the checked one | join, decrypt, sign |
| `inbox`, `inbox-own-deal` | The inbox is for another trustee, parameters or roster, or carries other commitments for this trustee's deal | join, decrypt, sign |
| `receive` | `dkg-receive` refused a share (it names the dealer) | join, decrypt, sign |
| `transcript` | The transcript on the chain does not carry this trustee's commitments, its joint key or this trustee's verification key | join, decrypt, sign |
| `chain-changed` | The chain's parameters or transcript differ from the ones checked at the ceremony | decrypt, sign |
| `ballots-peer-<id>` | Peer `<id>` read another ballot set | decrypt, sign |
| `partial-conflict` | The chain holds a different partial under this trustee's id | decrypt, sign |
| `partial-readback` | The partial read back from the chain is not the one computed | decrypt, sign |
| `ballots-changed` | The chain's ballot set changed after this trustee used it | sign |
| `tally-totals` | The console refused the signature: its totals differ from this trustee's | sign |
| `tally-differs` | The published tally is not this trustee's own combine | (none) |

## What the screens show (for task 6)

- Sign-in, then the three buttons with each step's state and `detail`/`error`.
- During the ceremony: the roster with each peer's check, the roster
  fingerprint, then the share and joint key fingerprints.
- During decryption: the ballot count per position, the ballot set
  fingerprint, the peers' ballot checks, partial recorded and read back, and
  `k of threshold` trustees decrypted.
- Before signing: the totals per contest and the Sign tally button (which sends
  them back).
- After publication: the published totals and whether they match.
- Alarms prominently, with their message.
