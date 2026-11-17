# Voter list and precinct check-in (`saksi-campaign serve --live`)

The live election's voters are one precinct's voter list, uploaded by the
presenter at setup. A voter checks in on a phone the way a voter checks in at
a precinct: gives their details, the system finds them on the list, the
Electoral Board (the presenter) looks at the person and approves, the voter
signs the list, and only then is the one ballot (the blind credential) handed
over. This file is the whole contract for the presenter page (`/admin/`), the
phone page (`/vote/`) and the board (`/board/`) for this part; the rest of the
live API is in `http-api.md`.

Every rule below is enforced by the console and covered by a test in
`packages/saksi-campaign/live_roll_test.go` and `live_checkin_test.go`.

## Starting the console

```
saksi-campaign serve --live ... --live-precinct 0001A
```

`--live-precinct` is the precinct number, four digits and a capital letter
(the shape of a real precinct number, RA 8189 Sec. 26). Default `0001A`. Any
other shape stops the console at start. Every screen names it with the label
the console sends, `"Precinct 0001A (demonstration)"`: the word
"demonstration" is always attached. An election keeps the precinct it was set
up with, even if the console restarts with another value.

## Conventions

Those of `http-api.md`, plus:

- Every error answer here has a stable `code` next to `error`:
  `{"error": "<one sentence>", "code": "<code>"}`. Pages branch on `code` and
  may show `error` as it is (the phone refusals are the sentences the screens
  use).
- **phone** access: public by role (no sign-in), and the route acts only on
  the check-in the phone's `saksi_checkin` cookie is bound to. No account, of
  any role, stands in for a check-in. Voter accounts in the accounts file are
  still accepted at start but obtain nothing.
- **admin** access: a signed-in `admin` session (`POST /api/login`).
- A date of birth is compared on the console and never returned by any route
  after the list is locked. The preview, before the lock, says only valid or
  not valid per row. No error message carries a date, and no log line does.
- The page never builds markup from anything a phone sent: a signature is
  numbers only, and the presenter page draws it itself.

## The list file

UTF-8 CSV (RFC 4180 quoting), at most 64 KiB:

```
# Fictional voters for the demonstration. No row is a real person.
last_name,first_name,middle_name,date_of_birth
Halimbawa,Uno,Pagsubok,1990-01-01
Sampol,Tres,,1992-03-03
```

- Lines starting with `#` are comments, anywhere in the file. Blank lines
  are skipped. A leading byte order mark is ignored. `CRLF` or `LF`.
- The first other row is the header, exactly
  `last_name,first_name,middle_name,date_of_birth` (spaces around a field are
  ignored).
- Each data row has 4 fields. `middle_name` may be empty.
- `date_of_birth` is `YYYY-MM-DD`: two-digit month and day, a real calendar
  date, from 1900-01-01, not after today (today anywhere on earth, i.e. now
  plus 14 hours in UTC).
- A name is letters (any script, with accents), spaces, hyphens, periods and
  apostrophes, at most 100 bytes after normalising spaces.
- At most 200 rows (a precinct's cap, RA 8189 Sec. 6). At least one.

### Normalising

Two forms of every name:

- **Display form** (shown, stored, fingerprinted): Unicode NFC, surrounding
  white space removed, every run of white space one space. Case and
  punctuation are kept: `"  Peña ,"` is `Peña`.
- **Match form** (find, and duplicate detection): decompose (NFKD), drop
  every combining mark, upper case, read every hyphen, dash and period as a
  space, drop apostrophes, collapse and trim white space. So `ñ` matches `n`
  (`PEÑA` = `Pena`), `José` = `JOSE`, `Dela-Cruz` = `dela  cruz`,
  `Ma. Clara` = `MA CLARA`, `O'Brien` = `OBRIEN`. The phone may type a name
  without the tilde, in any case, with or without the hyphen.

### Sorting and numbering

Rows are sorted by the match form of last name, then first name, then middle
name (ties: date of birth, then the display forms, then file order) and
numbered `1..N`: the sequence number (`seq`) a voter is told at the Voters'
Assistance Desk.

### Errors

Each error is `{"line": <n>, "code": "<code>", "message": "<sentence>"}`.
`line` is the CSV line (the file's first line is 1); `0` is the whole file.
Errors are sorted by line. A file with any error cannot be locked.

| `code` | Line | Meaning |
|---|---|---|
| `missing-last-name` | row | the last name is empty (or only punctuation) |
| `missing-first-name` | row | the first name is empty (or only punctuation) |
| `invalid-name` | row | a name (last, first or middle) has another character, or is over 100 bytes |
| `invalid-date` | row | the date of birth is not a real `YYYY-MM-DD` date from 1900 |
| `future-date` | row | the date of birth is after today |
| `duplicate` | row | same last name, first name and date of birth (match form) as an earlier line; the message names that line |
| `bad-row` | row | not 4 fields; the row is left out of `rows` |
| `bad-header` | header | the header is not the one above; nothing after it is read |
| `bad-csv` | where it broke | not valid CSV (a stray quote) or not UTF-8; nothing after it is read |
| `empty` | 0 | no header, or no data row |
| `too-many-rows` | 0 | more than 200 rows |
| `too-large` | 0 | over 64 KiB |

### The fingerprint

SHA-256, lower-case hex (64 digits), of this canonical text: UTF-8, every
line ending in one LF (`0x0A`) including the last, fields separated by one
TAB (`0x09`; no name can hold one):

```
saksi-voter-list-v1
precinct<TAB><precinct>
count<TAB><N>
<seq><TAB><last_name><TAB><first_name><TAB><middle_name><TAB><date_of_birth>
...one line per row, in seq order
```

Names are in display form; an empty middle name is an empty field (two TABs
in a row). The pages show the first 16 hex digits (`fingerprint_short`) with
the full value on demand. Anyone holding the CSV and the precinct value can
recompute it; a changed character in any row, a row added or removed, or
another precinct gives another fingerprint. The fingerprint is kept by the
console and shown on the board; it is not written to the ledger.

**Test vector.** Precinct `0001A`, file:

```
# Fictional voters for the documentation's worked example.
last_name,first_name,middle_name,date_of_birth
Sampol,Tres,,1992-03-03
Halimbawa,Uno,Pagsubok,1990-01-01
Peña,  Dos ,Santos-Reyes,1991-02-02
```

Canonical text (`→` is a TAB, `↵` the LF):

```
saksi-voter-list-v1↵
precinct→0001A↵
count→3↵
1→Halimbawa→Uno→Pagsubok→1990-01-01↵
2→Peña→Dos→Santos-Reyes→1991-02-02↵
3→Sampol→Tres→→1992-03-03↵
```

Fingerprint `cc0ad92dc0fce5cd088bde29bd4f6c03f3d66122e4fe06d4f44425851273dd75`,
short `cc0ad92dc0fce5cd`. (`Peña` is NFC: `50 65 c3 b1 61`.) To check by hand:

```
printf 'saksi-voter-list-v1\nprecinct\t0001A\ncount\t3\n1\tHalimbawa\tUno\tPagsubok\t1990-01-01\n2\tPe\xc3\xb1a\tDos\tSantos-Reyes\t1991-02-02\n3\tSampol\tTres\t\t1992-03-03\n' | shasum -a 256
```

## Check-in states

Each list entry is in one state:

```
not_checked_in --declare--> at_desk --approve--> approved --sign--> signed --issue/sign--> credential_issued
      ^                        |                    |                 |
      +-------refuse-----------+                    |                 |
      +-------reset------------+--------------------+-----------------+
```

| State | Meaning | Next |
|---|---|---|
| `not_checked_in` | nobody has checked in as this voter | a phone's `declare` |
| `at_desk` | a phone matched the entry and accepted the declaration; waiting for the Electoral Board | `approve`, `refuse`, `reset` |
| `approved` | the Board confirmed the person; waiting for the signature | the phone's `sign`, `reset` |
| `signed` | the voter signed the list (or recorded "I cannot sign") | the phone's issuance, `reset` |
| `credential_issued` | the one credential for this entry was issued | nothing, ever (no reset, no replacement) |

- `refuse` (at the desk only) and `reset` (any state before
  `credential_issued`) return the entry to `not_checked_in`, drop its
  signature and its open issuance session, and **end the phone's cookie**:
  that phone's poll then answers `refused` or `reset` and every other route
  refuses it. The real voter can then check in.
- "Checked in" in the counts is `signed` plus `credential_issued`: the
  voters who signed the list.
- Check-in (`find`, `declare`), `approve` and the phone's `sign` are open
  only while the election is `open`. The poll, the list, `refuse` and
  `reset` work in every state.
- State changes are written to the run's `private/checkin.json` (atomically,
  fsynced) before the answer is sent, and survive a restart.

## The phone's cookie

`declare` sets:

```
Set-Cookie: saksi_checkin=<43 chars, base64url of 32 random bytes>; Path=/api/live/; Max-Age=43200; HttpOnly; Secure; SameSite=Strict
```

- The page never reads it (HttpOnly); the browser sends it with every
  `/api/live/` call. `fetch` from the same origin sends it by default
  (`credentials: "same-origin"`).
- `Secure`: the page must be served over HTTPS (or `http://localhost`, which
  browsers treat as secure).
- The console stores only `SHA-256("saksi.live.checkin.v1" 0x00 <election
  id> 0x00 <token>)`, so a token is bound to one election: in the next
  election it is no check-in. Comparison is constant time.
- One phone holds one check-in at a time: `declare` from a phone whose
  check-in is `at_desk`, `approved` or `signed` is refused
  (`checkin-in-progress`). Once its voter is `credential_issued` the phone
  may check in another voter (a new cookie replaces the old one).
- The ballot relay (`POST /api/live/ballot`) never sees the cookie: the
  console drops the `Cookie` header before that handler runs.
- Lose the cookie (another browser, cleared data) and the phone has no
  check-in: the presenter resets the entry (if no credential was issued)
  and the voter checks in again.

## The signature

The phone sends either strokes or "I cannot sign", never both:

```json
{"strokes": [[[120, 210], [124, 215], [131, 222]], [[400, 180], [410, 190]]]}
```

```json
{"cannot_sign": true}
```

- A stroke is one pen-down to pen-up: a list of `[x, y]` points. `x` and `y`
  are **integers** in a 1000 × 400 box: `0 <= x <= 1000`, `0 <= y <= 400`,
  origin top left. The phone scales its drawing box to that box (keep a 5:2
  box to avoid distortion).
- Caps: at most 64 strokes, each 1 to 1000 points, at most 4000 points in
  all, body at most 64 KiB (413 above it). Anything else (a fraction, a
  string, a third number, another field, an image) is 400 `bad-signature` or
  400 `invalid JSON body`.
- `cannot_sign` is recorded on the list as the Board records a thumbmark at
  a real precinct; issuance treats it as a signature.
- The presenter page draws the strokes from these numbers (for example as
  polylines on a canvas or an SVG it builds itself, scaled from the 1000 ×
  400 box). Nothing a phone sent is ever inserted as markup.

## Routes

| Route | Access | States |
|---|---|---|
| `POST /api/live/voter-list/preview` | admin | any (no election needed) |
| `POST /api/live/elections` (with the list) | admin | see `http-api.md` |
| `GET /api/live/voter-list` | admin | any, once an election exists |
| `POST /api/live/desk/approve` | admin | open |
| `POST /api/live/desk/refuse` | admin | any |
| `POST /api/live/desk/reset` | admin | any |
| `POST /api/live/checkin/find` | phone, rate limited | open |
| `POST /api/live/checkin/declare` | phone, rate limited | open |
| `GET /api/live/checkin` | phone | any |
| `POST /api/live/checkin/sign` | phone | open |
| `POST /api/live/issue/presign`, `/issue/sign` | phone | open; check-in `signed` |
| `GET /api/live/election`, `GET /api/board/<run>` | public | counts and fingerprint only |

With live mode off every route answers 404; before any election, the routes
that need one answer 404 `{"error": "no live election has been set up"}`
(no `code`). An election made by an older console, with no list, answers
409 `no-voter-list` on the check-in, desk and issuance routes.

### `POST /api/live/voter-list/preview` (admin)

Parses a list with the same rule as setup and changes nothing: no file, no
state.

```json
{"csv": "<the file's text>"}
```

Body at most 192 KiB (413). Answer 200, always (a list in error is still a
200 with `valid: false`):

```json
{"precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
 "valid": true, "count": 3, "max_rows": 200,
 "rows": [{"seq": 1, "line": 4, "last_name": "Halimbawa", "first_name": "Uno",
           "middle_name": "Pagsubok", "date_of_birth_valid": true}, "..."],
 "errors": [],
 "fingerprint": "cc0ad92d...dd75", "fingerprint_short": "cc0ad92dc0fce5cd"}
```

- `rows` are sorted and numbered; with errors the numbering is provisional.
  Rows with `bad-row` are not in `rows`. `count` is `rows.length`.
- `date_of_birth_valid` is false for `invalid-date` and `future-date`. The
  date itself is never in the answer.
- `fingerprint` and `fingerprint_short` are `""` unless `valid`.
- `errors` as under **Errors**.

The presenter page: run the preview on the chosen file, show the table, the
errors, the count and the fingerprint, and enable "Confirm and lock the
list" only when `valid`. Confirming sends the same text and this
`fingerprint` in the setup request.

### `POST /api/live/elections` (admin)

`http-api.md`'s body plus two fields, both required:

```json
{"title": "...", "positions": [...], "trustees": 5, "threshold": 3,
 "voter_list": "<the same CSV text the preview had>",
 "voter_list_fingerprint": "<the preview's fingerprint>"}
```

Body at most 192 KiB. The list is parsed again (same rule, the console's own
precinct) and the election is **not created** unless it is valid, non-empty
and has that fingerprint:

| Status, `code` | When |
|---|---|
| 400 `voter-list-missing` | `voter_list` empty or absent |
| 400 `voter-list-invalid` | the list has an error or no row; preview it to see which |
| 400 `voter-list-unconfirmed` | `voter_list_fingerprint` empty or absent |
| 400 `voter-list-changed` | the list's fingerprint is not `voter_list_fingerprint` (the file changed since the preview, or another precinct) |

On success the list is locked: written to the run's `private/voter-list.json`
with every entry `not_checked_in` in `private/checkin.json`, before
`live.json`. No route changes a locked list. The 201 answer is the election
view (below). While the current election is still in `setup`, a retry does
not use the posted fields, the list included (`http-api.md`).

### `GET /api/live/voter-list` (admin)

The election-day list: every entry with its status and signature, never a
date of birth.

```json
{"election_id": "live-20261120-...", "election_state": "open",
 "precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
 "fingerprint": "<64 hex>", "fingerprint_short": "<16 hex>", "count": 20,
 "counts": {"not_checked_in": 16, "at_desk": 1, "approved": 0, "signed": 1,
            "credential_issued": 2, "checked_in": 3},
 "desk": [{"seq": 7, "last_name": "Sampol", "first_name": "Tres", "middle_name": "",
           "status": "at_desk"}],
 "entries": [{"seq": 1, "last_name": "Halimbawa", "first_name": "Uno", "middle_name": "Pagsubok",
              "status": "credential_issued",
              "signature": {"strokes": [[[120, 210], [124, 215]]]}},
             {"seq": 2, "...": "...", "status": "signed", "signature": {"cannot_sign": true}},
             {"seq": 3, "...": "...", "status": "not_checked_in"}]}
```

- `entries` is every entry in `seq` order; `entries[i].seq` is `i + 1`.
- `desk` is the entries `at_desk`, oldest request first. The presenter page
  shows them on top ("At the desk", the name in large type, Approve and
  Refuse). The order is kept only while someone is at the desk.
- `signature` is present from `signed` on (until a reset).
- Errors: 404 before any election; 409 `no-voter-list`.

Poll it (every 1 to 2 s while the panel is open). An entry that leaves
`desk` between polls was approved, refused or reset by another tab: the page
drops it and shows its new status.

### `POST /api/live/desk/approve` (admin; open)

```json
{"seq": 7}
```

`at_desk` → `approved`. Answer 200, the entry as in `entries`:

```json
{"seq": 7, "last_name": "Sampol", "first_name": "Tres", "middle_name": "", "status": "approved"}
```

| Status, `code` | When |
|---|---|
| 404 `no-such-entry` | no entry with that `seq` |
| 409 `wrong-state` | the entry is not `at_desk` (approved by another tab, refused, reset) |
| 409 `not-open` | the election is not open |

### `POST /api/live/desk/refuse` (admin)

```json
{"seq": 7}
```

`at_desk` → `not_checked_in`; the phone's cookie ends with outcome
`refused`. Answer 200, the entry (`status: "not_checked_in"`). 404
`no-such-entry`; 409 `wrong-state` if the entry is not `at_desk`; 409
`already-issued` for an issued entry.

### `POST /api/live/desk/reset` (admin)

```json
{"seq": 7}
```

`at_desk`, `approved` or `signed` → `not_checked_in`; the signature and any
open issuance session for the entry are dropped; the phone's cookie ends
with outcome `reset`. Answer 200, the entry. 404 `no-such-entry`; 409
`wrong-state` for an entry already `not_checked_in`; **409 `already-issued`
once a credential is issued: there is no reset and no replacement** (the
rule of the ink). The page asks for an inline confirmation first.

### `POST /api/live/checkin/find` (phone; open; rate limited)

```json
{"last_name": "Sampol", "first_name": "Tres", "date_of_birth": "1992-03-03"}
```

Looks for the one entry with that last name and first name (match form) and
date of birth. Changes nothing and sets no cookie. Answer 200:

```json
{"precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
 "entry": {"seq": 7, "last_name": "Sampol", "first_name": "Tres", "middle_name": ""}}
```

| Status, `code` | `error` (the screen's sentence) |
|---|---|
| 404 `not-on-list` | "No voter with these details is on this precinct's list. Check the spelling or see the Electoral Board." The same answer, byte for byte, whichever field was wrong. |
| 409 `already-checked-in` | "This voter has already checked in. See the Electoral Board." (the entry is `at_desk` or later) |
| 400 `bad-date` | `date_of_birth` is not a `YYYY-MM-DD` date (a form error, said before any lookup) |
| 400 `bad-request` | a name over 400 bytes |
| 409 `not-open` | the election is not open |
| 429 `rate-limited` | too many tries from this address; `Retry-After` in seconds |

### `POST /api/live/checkin/declare` (phone; open; rate limited)

The same details again, and the declaration:

```json
{"last_name": "Sampol", "first_name": "Tres", "date_of_birth": "1992-03-03", "declaration": true}
```

Matches again (find's answers and errors apply) and, when the entry is
`not_checked_in`, moves it to `at_desk`, binds a new token to it and sets
the cookie. Answer 200, the poll view (below) with `state: "at_desk"`.
Two phones that found the same entry: the first `declare` wins, the second
gets 409 `already-checked-in` and no cookie.

| Status, `code` | When |
|---|---|
| 400 `declaration-required` | `declaration` absent or not `true` (checked first) |
| 409 `checkin-in-progress` | this phone already holds a check-in at `at_desk`, `approved` or `signed` |
| as for find | `not-on-list`, `already-checked-in`, `bad-date`, `not-open`, `rate-limited` |

### `GET /api/live/checkin` (phone)

The phone's check-in, for the waiting screen and for a reload:

```json
{"state": "approved", "election_id": "live-...", "election_state": "open",
 "precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
 "entry": {"seq": 7, "last_name": "Sampol", "first_name": "Tres", "middle_name": ""}}
```

`state` is the entry's state, or for an ended cookie `refused` or `reset`
(then no `entry`). 404 `no-checkin` when the phone has no cookie or one the
console does not know (another election, forged, lost). Poll every 1 to 2 s
while waiting.

Where the phone goes on load or reload:

| Poll answer | Screen |
|---|---|
| 404 `no-checkin` | the check-in form |
| `at_desk` | "Waiting for the Electoral Board" |
| `approved` | the signature screen |
| `signed` | the credential step (issuance) |
| `credential_issued` | the ballot screens as built |
| `refused` | "The Electoral Board did not confirm your identity." |
| `reset` | the check-in form (the Board cleared the check-in) |
| any, with `election_state` not `open` | what the election state calls for (closed: voting has ended) |

### `POST /api/live/checkin/sign` (phone; open)

The signature body above. `approved` → `signed`. Answer 200, the poll view
with `state: "signed"`.

| Status, `code` | When |
|---|---|
| 400 `bad-signature` | see **The signature** (also `invalid JSON body` for a non-integer) |
| 413 | body over 64 KiB |
| 403 `no-checkin` | no check-in, or one the Board ended |
| 409 `wrong-state` | the check-in is not `approved` |
| 409 `not-open` | the election is not open |

### `POST /api/live/issue/presign` and `POST /api/live/issue/sign` (phone; open)

Bodies and answers as in `http-api.md`. The console issues only to the
check-in the cookie is bound to, only in state `signed`, once per entry for
ever: the entry moves to `credential_issued` in `private/checkin.json`
before `s_iss` is sent.

| Status, `code` | When |
|---|---|
| 403 `no-checkin` | no check-in cookie, one the console does not know, or one the Board ended; a signed-in account of any role changes nothing |
| 409 `not-signed` | the check-in is `at_desk` or `approved` |
| 409 `already-issued` | the entry has its credential; a lost credential is not reissued |
| 409 `no-voter-list` | the election has no list |
| 409 | the election is not open (no `code`, as in `http-api.md`) |

**Never retry `issue/sign`.** If its answer is lost, the entry is spent with
no credential and cannot be reset (decision 5: no replacement).

### Counts in the election view and on the board

`GET /api/live/election` gains (no names, no dates):

```json
{"precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
 "voter_list_fingerprint": "<64 hex>", "voter_list_fingerprint_short": "<16 hex>",
 "counts": {"voters_on_list": 20, "voters_on_roll": 20, "checked_in": 3,
            "credentials_issued": 3, "...": "the existing counts"}}
```

`GET /api/board/<run>` gains the same under `live`, plus the sentence to
show next to them:

```json
{"live": {"precinct": "0001A", "precinct_label": "Precinct 0001A (demonstration)",
          "voter_list_fingerprint": "<64 hex>", "voter_list_fingerprint_short": "<16 hex>",
          "voter_list_note": "The list is kept by the election console. It is not written to the ledger.",
          "counts": {"voters_on_list": 20, "voters_on_roll": 20, "checked_in": 3,
                     "credentials_issued": 3, "...": "..."}}}
```

`integrity.voters` on the board is the list count. `voters_on_roll` is the
older name of `voters_on_list` and has the same value.

## Rate limit

`find` and `declare` share one token bucket per caller address (the
connection's address; every loopback address is one): a burst of 20, then
one more every 3 seconds. Three honest phones behind one address with a few
typos each stay well inside it (a check-in costs two: find and declare).
Over it: 429 `rate-limited` with `Retry-After`. The addresses are kept in
memory only, never logged or written; at 4096 addresses in use a new address
is refused until buckets refill. A guess at a date of birth costs one try,
so 36,500 dates take about 30 hours from one address.

The typed details are not a secret and are not the security: the Board's
approval at the desk is the gate, and the list is matched only to find the
entry.

## What the console keeps

| File (in the run folder) | What | Public |
|---|---|---|
| `private/voter-list.json` (0600) | the locked list: precinct, fingerprint, every row with its date of birth | never |
| `private/checkin.json` (0600) | per entry: state, the token's hash, the desk order while at the desk, the signature; the ended tokens' hashes with their outcome | never |
| `live.json` | the precinct, the fingerprint and the list count | no |

Neither private file holds a time, an address, or anything from issuance (no
commitment, challenge, session or signature). The console learns which list
entry received a credential; it never learns which ballot belongs to which
entry: the ballot relay drops the cookie, logs nothing, and the credential
is blind. A restart reloads both files: every state and every cookie stays
valid. `tools/live-reset.sh` deletes the run folder and with it the list.
