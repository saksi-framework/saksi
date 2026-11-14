# Live election wire format (`saksi-demo live`)

This is the contract between the live election's crypto steps and everything
that calls them: the console (`saksi-campaign serve` in live mode), each trustee
process (`saksi-campaign trustee --id N`), and the phone's WebAssembly
(`packages/saksi-wasm`). It matches the code in `packages/saksi-live` (voter
and dealer steps), `packages/saksi-auditor/src/live.rs` (checks the auditor
already makes) and `packages/saksi-demo/src/live.rs` (the CLI and its files).
The tests that hold it to the code are `packages/saksi-demo/tests/live_cli.rs`,
`packages/saksi-bulletin/chaincode/live_artifacts_test.go` and
`live_wasm_ballots_test.go`, and `tools/live/test-wasm.sh` (the phone's
WebAssembly run under node).

Format version: `saksi-live-wire-v1` (`saksi_live::WIRE_FORMAT`, reported by
the phone's `version()`).

This is a later build, not the study build. The study's subcommands and
outputs are unchanged.

## Calling convention

```
saksi-demo live <op> < input.json > output.json
```

- **Input:** exactly one JSON object on stdin. Unknown fields are refused.
- **Success:** exit 0, one JSON object and a newline on stdout, nothing on
  stderr.
- **Failure:** exit 1, nothing on stdout, one JSON object
  `{"error": "<message>"}` on stderr. Error messages never contain secret
  material. A malformed input reports only its category and position
  (`input is the wrong shape for this op (...) (line 1, column 40)`), because
  a parser message could quote a secret value.
- **One party per call.** Each op receives only the secrets of the party that
  runs it. The issuer's, a trustee's receive key and a trustee's share are
  named by **file path** and never travel on stdin or stdout. The voter ops
  are the exception: the voter's state and credential travel on stdin and
  stdout, because the voter's process is the phone itself (the CLI forms
  exist for tests and for the Go end-to-end test).

### Encodings

| Kind | Encoding |
|---|---|
| point | 32-byte compressed ristretto255, lowercase hex (64 chars) |
| scalar | 32-byte canonical little-endian, lowercase hex (64 chars) |
| protobuf message | canonical `prost` encoding of the `saksi.protocol.v1` message, lowercase hex. This is the exact string the chaincode function takes. |
| bytes | lowercase hex |
| trustee id | integer `1..=n` in DKG ops; the string `"1".."n"` inside protobuf messages and in `trustee_id` fields of tally ops (see each op) |

Decoding is strict: upper-case hex is accepted, but a non-canonical scalar,
an invalid point, the identity where a public key is expected, or a value of
the wrong length is an error naming the field. A value that is not hex at all
gives `<field> is not valid hex`, without quoting the offending character.

### Fingerprints

Every `*fingerprint` field is the first 16 bytes (128 bits) of a 32-byte
SHA-256 digest, in upper-case hex, in eight groups of four digits for reading
aloud: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` (39 characters). Where a
fingerprint stands for a digest that is also output (`roster_digest`,
`ballots_digest`), the full 32 bytes are in that field and are what processes
compare mechanically; the fingerprint is for people. 128 bits keeps a forged
roster, share or ballot set that shows the genuine fingerprint (or a set of
forged rosters that all show one fingerprint, which a full relay attack on
the DKG would need) out of reach even with days of precomputation.

### Ids

`election_id`, position ids and candidate ids are 1 to 64 bytes of ASCII
letters, digits, `-`, `_` and `.`. Contest ids are `<position>/<candidate>`,
at most 127 bytes in all.
Trustee ids are `"1".."n"` in order, because the DKG evaluates trustee `k`'s
share at `x = k` and every verifier (auditor, chaincode) maps a trustee id to
its 1-based position in `ElectionParameters.trustee_ids`.

### Binding context

Every NIZK is made under the binding context `saksi-auditor-v1` (hex
`73616b73692d61756469746f722d7631`), the generator's, so the auditor, the
chaincode and the board read a live election exactly as a generated one.

## Secret files

Written by the CLI with mode `0600` and `O_CREAT|O_EXCL`: an existing file is
never overwritten (`... already exists; refusing to overwrite a secret file`).
Read only when the mode grants nothing to group or other users; otherwise the
op fails with `... is readable by other users (mode 644); want 0600`. Each is
one JSON object with a `kind`:

| kind | written by | fields |
|---|---|---|
| `saksi-live-issuer-key-v1` | `issuer-keygen` | `secret` (scalar), `public_key` (point) |
| `saksi-live-issuer-session-v1` | `issue-presign` | `k` (scalar, the signing nonce) |
| `saksi-live-trustee-receive-key-v1` | `trustee-keygen` | `trustee_id` (int), `secret` (scalar), `public_key` (point) |
| `saksi-live-trustee-share-v1` | `dkg-receive` | `election_id`, `trustee_id` (int), `threshold`, `trustees`, `share` (scalar), `verification_key` (point), `joint_public_key` (point), `fingerprint`, `roster_digest` (32-byte hex) |

Every read checks that the secret matches its recorded public point.

## Op summary

| Op | Run by | Secrets it reads |
|---|---|---|
| `election-params` | console | none |
| `issuer-keygen` | console | writes the issuer key file |
| `issue-presign` | console (issuer) | issuer key file; writes a session file |
| `issue-sign` | console (issuer) | issuer key file; consumes the session file |
| `voter-begin`, `voter-blind`, `voter-finalize` | voter (phone) | voter state on stdin |
| `ballot` | voter (phone) | credential on stdin |
| `trustee-keygen` | trustee `N` | writes its receive key file |
| `dkg-deal` | trustee `N` | its receive key file |
| `dkg-receive` | trustee `N` | its receive key file; writes its share file |
| `dkg-roster` | console (relay), anyone | none |
| `dkg-transcript` | console | none |
| `aggregate` | anyone | none |
| `partial` | trustee `N` | its share file |
| `combine` | anyone (each trustee before signing) | none |
| `sign-tally` | trustee `N` | its share file |
| `tally-assemble` | console | none |
| `verify-live` | anyone | none |

Order of a live election:

```
election-params -> CreateElection
trustee-keygen x n -> (roster of all n receive keys) -> dkg-roster
dkg-deal x n -> (relay) -> dkg-receive x n -> compare roster_fingerprint
dkg-transcript -> PublishDKGTranscript -> compare joint key and verification keys
per voter: voter-begin -> issue-presign -> voter-blind -> issue-sign -> voter-finalize
per voter, per position: ballot -> SubmitBallot
CloseElection
per trustee: partial (over the ballots read back) -> SubmitPartialDecryption (one per contest)
per trustee: combine, sign-tally (over the same ballots and the on-chain partials)
tally-assemble -> PublishTally
verify-live
```

## Console and issuer

### `election-params`

Input:

```json
{
  "election_id": "live-2026",
  "positions": [
    {"id": "president", "candidates": ["alice", "bob", "carol"]},
    {"id": "secretary", "candidates": ["dan", "eve", "fay"]}
  ],
  "trustees": 5,
  "threshold": 3,
  "issuer_public_key": "<point>"
}
```

Output:

```json
{
  "params": "<hex ElectionParameters: the CreateElection argument>",
  "election_id": "live-2026",
  "contest_ids": ["president/alice", "president/bob", "president/carol",
                  "secretary/dan", "secretary/eve", "secretary/fay"],
  "trustee_ids": ["1", "2", "3", "4", "5"],
  "threshold": 3
}
```

Refuses an empty position list, a position with no candidates, a repeated
position or candidate, a bad id, `threshold` outside `1..=trustees`, an issuer
key that is not a non-identity point, and **a contest id longer than 127
bytes**:

```
contest id "<id>" is 128 bytes; position and candidate ids together must be at most 127 bytes including the '/'
```

The 127-byte cap exists because a partial decryption's Chaum-Pedersen context
length-prefixes the contest id with 8 big-endian bytes, and
`partial_decrypt_v2` takes that context as UTF-8: the prefix's low byte must be
ASCII. An election that could not be decrypted is therefore never created.
The parameters bind the issuer key, which turns on the chaincode's `issuer`
and `selection` gates.

### `issuer-keygen`

Input `{"key_file": "/path/issuer.key"}`. Writes the issuer key file. Output
`{"public_key": "<point>"}`, the value `election-params` takes.

### `issue-presign`

Issuer step 1 (`issuer_pre_sign`). Input:

```json
{"issuer_key_file": "/path/issuer.key",
 "blinded_commitment": "<point from voter-begin>",
 "session_file": "/path/sessions/<account>.json"}
```

Writes the session file holding the nonce `k`. Output `{"r": "<point>"}`.

### `issue-sign`

Issuer step 2 (`issuer_sign`). Input:

```json
{"issuer_key_file": "/path/issuer.key",
 "session_file": "/path/sessions/<account>.json",
 "e_prime": "<scalar from voter-blind>"}
```

Claims the session **atomically** by renaming `session_file` to
`<session_file>.claimed.<32 random hex>`, reads the claimed file, deletes it,
and only then signs. Of two concurrent calls on one session only one rename
succeeds; the other fails without signing:

```
session <path> is already used or missing (<os error>); not signing
```

A session recreated later under the same name is a different file, so no path
signs two challenges with one nonce (two responses under one nonce would
reveal the issuer key). If the claimed file cannot be deleted the op does not
sign. A crash after the rename loses the session without signing. Output
`{"s_iss": "<scalar>"}`.

The console must also keep issuance sessions few and short-lived: blind
Schnorr signatures lose unforgeability when an attacker can hold many sessions
open at once (the ROS attack). One open session per account, and a cap on
concurrent sessions, is enough for the demo's three voters.

### `dkg-transcript`

Input:

```json
{"params": "<hex ElectionParameters>",
 "dealers": [{"dealer_id": 1, "commitments": ["<point>", "..."]}, "..."]}
```

`dealers` must be exactly `1..=n` once each (any order); each `commitments` is
the `dkg-deal` output of that dealer. Output:

```json
{"dkg": "<hex DKGTranscript: the PublishDKGTranscript argument>",
 "election_id": "live-2026",
 "joint_public_key": "<point>",
 "joint_key_fingerprint": "7A1B-2C3D-4E5F-6071-8293-A4B5-C6D7-E8F9",
 "verification_keys": [
   {"trustee_id": "1", "verification_key": "<point>", "fingerprint": "1A2B-3C4D-5E6F-7081-90A1-B2C3-D4E5-F607"},
   "..."]}
```

The transcript is the library's `DkgOutput::to_protocol_transcript` over the
commitments alone (no complaints; trustee ids `"1".."n"` in order). It is then
run through the auditor's transcript checks, which also derive
`joint_public_key` and every `verification_key`. Refuses a transcript whose
joint key is the identity (`... joint public key is the identity: every vote
would be in the clear`) or in which any trustee's verification key is the
identity. Every op that takes `params` and `dkg` makes the same refusal.

### `tally-assemble`

Input:

```json
{"params": "<hex>", "dkg": "<hex>",
 "ballots": ["<hex Ballot>", "..."],
 "partials": ["<hex PartialDecryption>", "..."],
 "totals": [2, 1, 0, 1, 0, 2],
 "signatures": [{"trustee_id": "1", "signature": "<64-byte hex>"}, "..."]}
```

Aggregates `ballots` itself (see **Ballot sets**), recomputes the totals from
`partials` (as `combine`) and refuses if `totals` differ; refuses a signature
that does not verify over these totals under its trustee's verification key,
an unknown trustee and a repeated one. It does **not** enforce the threshold,
so the console can assemble a tally two trustees signed and show the
chaincode refusing it. Output, plus the ballot-set fields:

```json
{"tally": "<hex TallyResult: the PublishTally argument>",
 "election_id": "live-2026", "totals": [2, 1, 0, 1, 0, 2],
 "signatures": 3, "threshold": 3, "meets_threshold": true}
```

The tally carries every partial in `partials` and the signatures in input
order.

## Voter (phone)

The phone's WebAssembly calls the same Rust functions directly:
`saksi_live::issuance::{voter_begin, voter_blind, voter_finalize}`,
`saksi_live::ballot::build_ballot_with_opening` (the `ballot` builder, plus
the Benaloh opening) and `saksi_live::election::tracking_code`. Their argument
and result types serialize to exactly the JSON below; the exports themselves
are in **WebAssembly (phone)**.

### `voter-begin`

Input `{}`. Output:

```json
{"blinded_commitment": "<point: send to issue-presign>",
 "state": {"s_cred": "<scalar>", "b": "<scalar>"}}
```

`state` is secret; the phone keeps it for `voter-blind`.

### `voter-blind`

Input:

```json
{"state": {"s_cred": "...", "b": "..."},
 "r": "<point from issue-presign>",
 "issuer_public_key": "<point>"}
```

Output:

```json
{"e_prime": "<scalar: send to issue-sign>",
 "state": {"s_cred": "<scalar>", "r_prime": "<point>", "alpha": "<scalar>", "beta": "<scalar>"}}
```

### `voter-finalize`

Input:

```json
{"state": {"s_cred": "...", "r_prime": "...", "alpha": "...", "beta": "..."},
 "s_iss": "<scalar from issue-sign>",
 "issuer_public_key": "<point>"}
```

Refuses a response that does not unblind into a valid issuer signature.
Output:

```json
{"credential": {"s_cred": "<scalar>", "signature_r": "<point>", "signature_s": "<scalar>"},
 "commitment": "<point C = s_cred·G>"}
```

`credential` is secret (it votes); the phone stores it in IndexedDB.

### `ballot`

One position's record, built as the generator's `build_record`. Input:

```json
{"params": "<hex ElectionParameters>",
 "dkg": "<hex DKGTranscript>",
 "credential": {"s_cred": "...", "signature_r": "...", "signature_s": "..."},
 "position_id": "president",
 "choice": 1}
```

`choice` is the 0-based index of the candidate within the position. Refuses a
credential the election's issuer did not sign, a transcript that is not the
election's, a transcript whose joint key is the identity, an unknown position
and a choice outside its candidates. Output:

```json
{"ballot": "<hex Ballot: the SubmitBallot argument>",
 "election_id": "live-2026",
 "position_id": "president",
 "contest_ids": ["president/alice", "president/bob", "president/carol"],
 "nullifier": "<32-byte hex>",
 "tracking_code": "BC-7F3A-92C1",
 "ballot_fingerprint": "4F2A-91C3-07B8-D6E5-1A2B-3C4D-5E6F-7081"}
```

`tracking_code` is `BC-` and the first 8 hex digits of the nullifier in upper
case, split 4-4: the board's `formatTrackingCode` (both give the empty string
for a nullifier shorter than 4 bytes). **The tracking code identifies the
voter's slot for a position, not a particular ballot:** the nullifier is per
voter per position, so every ballot a voter builds for a position, including
one discarded after a Benaloh challenge, has the same code.

`ballot_fingerprint` identifies the particular ballot. It is

```
ballot_fingerprint = upper_hex( SHA-256(ballot_bytes)[0..16] ) in eight groups of four
```

where `ballot_bytes` are the record's protobuf bytes exactly as submitted: the
`ballot` hex decoded. The chaincode stores those bytes unchanged and
`GetBallot` / `GetBallots` return them as hex, so the board and the console
compute the same fingerprint from the chain record alone, with no key and no
other input. It is the first half of the same SHA-256 as the opening's
`ballot_digest`. Two ballots for the same voter and position share the
tracking code but, built with fresh randomness, never the fingerprint. The
board should show it next to the tracking code, so a voter can see that the
recorded ballot is the one the phone showed.

Anyone computing the fingerprint from the chain (the board, the console, a
trustee) must hash the raw stored bytes, the `GetBallot` / `GetBallots` hex
decoded, and never decode and re-marshal the record first: Go's
`proto.Marshal` is not guaranteed to reproduce prost's bytes. The chaincode
checks the parsed fields and stores the submitted bytes, but does not require a
canonical encoding, so a relay could resubmit a voter's genuine ballot
re-encoded (an extra unknown field, reordered fields, a non-minimal varint) and
the chain would accept it under a different fingerprint. A fingerprint on the
board that differs from the one the phone showed therefore has two possible
causes: a different ballot was recorded, or the same ballot was re-encoded on
its way to the chain. Either way the recorded bytes are not the bytes the phone
built, and the relay altered them.

### `benaloh-check`

The Benaloh challenge's check, the same function as the phone's
`benaloh_check` (`saksi_live::benaloh::check`), as a native process so a
challenged ballot can be checked by code other than the phone's.

**What it is for:** tests, and checking offline a challenged ballot that is
already superseded on the chain (the voter's fresh ballot with the same
nullifier is recorded). A challenged ballot is a valid, submittable ballot
until then (see **The Benaloh challenge**), so this op must never be wired to
a server route, and no server component (the console included) may accept,
hold or check a challenged ballot. Input:

```json
{"params": "<hex ElectionParameters>",
 "dkg": "<hex DKGTranscript>",
 "ballot": "<hex Ballot: the challenged one>",
 "opened": {"election_id": "live-2026", "position_id": "president",
            "nullifier": "<32-byte hex>", "tracking_code": "BC-7F3A-92C1",
            "slots": [{"contest_id": "president/alice", "plaintext": 0, "randomness": "<scalar>"},
                      {"contest_id": "president/bob",   "plaintext": 1, "randomness": "<scalar>"},
                      {"contest_id": "president/carol", "plaintext": 0, "randomness": "<scalar>"}]}}
```

`opened` is the phone's `benaloh_open` output (see **WebAssembly (phone)**).
Re-encrypts each slot under the transcript's joint key with the revealed
randomness and compares it with the ballot's ciphertext. Output:

```json
{"valid": true,
 "position_id": "president",
 "tracking_code": "BC-7F3A-92C1",
 "ballot_fingerprint": "4F2A-91C3-07B8-D6E5-1A2B-3C4D-5E6F-7081",
 "slots": [{"contest_id": "president/alice", "plaintext": 0, "reproduces": true}, "..."],
 "encoded_choice": 1,
 "encoded_candidate": "bob"}
```

`valid` is true iff every slot reproduces and exactly one slot holds 1 (the
rest 0); `encoded_choice` and `encoded_candidate` are then the candidate the
ballot encodes, else `null`. `position_id` is the position of the ballot it
checked and `ballot_fingerprint` that ballot's fingerprint (see `ballot`): the
caller compares both, and the candidate, with what the voter chose and was
shown. A randomness that is not a canonical scalar is a
slot that does not reproduce. Refused with an error (not a verdict): a ballot
or opening for another election, position or nullifier, a slot count that is
not the position's, or a slot whose contest id is not the election's.

## Trustee

### `trustee-keygen`

Input `{"trustee_id": 2, "key_file": "/path/t2/receive.key"}`. Writes the
receive key file. Output:

```json
{"trustee_id": 2, "receive_public_key": "<point>", "fingerprint": "5E6F-7081-1A2B-3C4D-0F1E-2D3C-4B5A-6978"}
```

`fingerprint` is `SHA-256("saksi.live.receive-key-fingerprint.v1" ||
compress(X))` shown as a fingerprint (see **Fingerprints**). The key is used only
to receive masked DKG shares.

### `dkg-deal`

Input:

```json
{"receive_key_file": "/path/t2/receive.key",
 "params": "<hex ElectionParameters>",
 "dealer_id": 2,
 "peers": [{"trustee_id": 1, "receive_public_key": "<point>"}, "...",
           {"trustee_id": 5, "receive_public_key": "<point>"}]}
```

`election_id`, `t` and `n` are read from `params` (whose trustee ids must be
`"1".."n"`), not from loose fields. `peers` is the **roster**: every trustee
`1..=n` once, **including the dealer itself**. The roster is refused on a
missing or repeated id, an identity or non-canonical point, a key that appears
twice, or a dealer key that is not this dealer's key file (`the roster's key at
id 2 is not this dealer's key file`). Draws a fresh `Dealer::random`
polynomial, wipes its coefficients after use, and outputs:

```json
{"election_id": "live-2026", "dealer_id": 2,
 "commitments": ["<point A_{2,0}>", "<point A_{2,1}>", "<point A_{2,2}>"],
 "masked_shares": [
   {"dealer_id": 2, "recipient_id": 1, "nonce": "<32-byte hex>",
    "ciphertext": "<32-byte hex>", "tag": "<32-byte hex>"},
   "... one per recipient 1..=n, including the dealer's own"],
 "roster_digest": "<32-byte hex>",
 "roster_fingerprint": "3C4D-5E6F-7081-1A2B-8E9F-A0B1-C2D3-E4F5"}
```

`masked_shares[k]` is for recipient `k + 1`. The relay forwards each one to its
recipient and the `commitments` to everyone.

#### Roster digest

```
roster_digest = SHA-256( "saksi.live.dkg-roster.v1"
                         || u64be(len(election_id)) || election_id
                         || u64be(n) || u64be(t)
                         || u64be(1) || compress(X_1) || ... || u64be(n) || compress(X_n) )
roster_fingerprint = upper_hex(roster_digest[0..16]) in eight groups of four
```

#### Share mask

For dealer `i` (receive key `x_i`, `X_i = x_i·G`) and recipient `j` (`X_j`),
with `X_i`, `X_j` taken from the roster:

```
dh   = compress(x_i · X_j)              (= compress(x_j · X_i))
okm  = SHA-512( "saksi.live.dkg-share.v2"
                || roster_digest
                || u64be(len(election_id)) || election_id
                || u64be(i) || u64be(j)
                || compress(X_i) || compress(X_j)
                || nonce || dh )
pad  = okm[0..32]      mk = okm[32..64]
ciphertext = scalar_bytes(f_i(j)) XOR pad
tag  = SHA-512( "saksi.live.dkg-share-tag.v1" || mk || ciphertext )[0..32]
```

`nonce` is 32 fresh random bytes per share. The tag is checked in constant time
before unmasking.

#### What the mask protects, and on what condition

Every receive key reaches the dealers and the recipients through the relay.
**The relay cannot read or forge a share provided every trustee confirms the
same roster digest** (each trustee page shows `roster_fingerprint`, and the
trustee processes compare it, task 4). With an authentic roster only `i` and
`j` can compute `dh`, and the tag stops the relay changing a share. Because the
digest is in the key derivation, a share masked under a substituted roster
fails the recipient's tag and is refused naming the dealer, and two trustees
shown different rosters report different fingerprints. **Without that
comparison the relay can substitute keys**: it can show every dealer a roster
holding its own keys, read every share, and re-mask them to the real
recipients, which would let it reconstruct the election key.

### `dkg-roster`

The roster check and digest that `dkg-deal` and `dkg-receive` make, with no
key: what the relay (the console) publishes with the roster, so a trustee can
compare the digest it was shown with the one it computes and with the other
trustees'. Input:

```json
{"params": "<hex ElectionParameters>",
 "peers": [{"trustee_id": 1, "receive_public_key": "<point>"}, "... the full roster"]}
```

The roster is checked as in `dkg-deal` (every id `1..=n` once, canonical
non-identity points, no key twice). Output, peers in id order:

```json
{"election_id": "live-2026", "threshold": 3, "trustees": 5,
 "peers": [{"trustee_id": 1, "receive_public_key": "<point>",
            "fingerprint": "5E6F-7081-1A2B-3C4D-0F1E-2D3C-4B5A-6978"}, "..."],
 "roster_digest": "<32-byte hex>",
 "roster_fingerprint": "3C4D-5E6F-7081-1A2B-8E9F-A0B1-C2D3-E4F5"}
```

`fingerprint` is each key's `trustee-keygen` fingerprint. The digest is only
as good as where it came from: a trustee still compares it with the digest the
other trustees' own hosts report (task 4), never only with the relay's.

### `dkg-receive`

Input:

```json
{"receive_key_file": "/path/t2/receive.key",
 "share_file": "/path/t2/share.json",
 "params": "<hex ElectionParameters>",
 "trustee_id": 2,
 "peers": [{"trustee_id": 1, "receive_public_key": "<point>"}, "... the full roster"],
 "dealers": [
   {"dealer_id": 1, "receive_public_key": "<point>",
    "commitments": ["<point>", "..."],
    "masked_share": {"dealer_id": 1, "recipient_id": 2, "nonce": "...", "ciphertext": "...", "tag": "..."}},
   "... one per dealer 1..=n, including this trustee's own deal"]}
```

`election_id`, `t` and `n` come from `params`. The roster is checked as in
`dkg-deal`, and this trustee's own key must be at its own id (`the roster's
key at id 2 is not this trustee's key file`). For every dealer: checks its
`receive_public_key` is exactly the roster's key at that id, the masked share
is addressed to this trustee and from that dealer, the dealer has `threshold`
commitments, the tag verifies under this roster, the unmasked value is a
canonical scalar, and `verify_share` accepts it against the dealer's
commitments. On the first failure it refuses, writes no share file, and names
the dealer:

- `dealer 5: receive_public_key is not the roster's key for that id`
- `dealer 4: masked share failed authentication (tampered, masked under another roster, or not for this trustee's key)`
- `dealer 2: share does not verify against the dealer's commitments`

It also refuses a joint key or a verification key that is the identity.
Otherwise it sums the shares into this trustee's key share, writes the share
file, and outputs:

```json
{"election_id": "live-2026", "trustee_id": 2,
 "verification_key": "<point s_2·G>",
 "fingerprint": "1A2B-3C4D-5E6F-7081-90A1-B2C3-D4E5-F607",
 "joint_public_key": "<point>",
 "joint_key_fingerprint": "7A1B-2C3D-4E5F-6071-8293-A4B5-C6D7-E8F9",
 "roster_digest": "<32-byte hex>",
 "roster_fingerprint": "3C4D-5E6F-7081-1A2B-8E9F-A0B1-C2D3-E4F5"}
```

`fingerprint` is `SHA-256("saksi.live.share-fingerprint.v1" || compress(vk))`
shown as a fingerprint (see **Fingerprints**). `joint_key_fingerprint` is
`SHA-256("saksi.live.joint-key-fingerprint.v1" || compress(Y))` shown the same
way; `dkg-transcript` and the phone (`election_info`) show the same value, so
people can confirm the phone encrypts under the key the trustees made.

**The trustee process must compare**:
- `roster_fingerprint` with every other trustee's (see **What the mask protects, and on what condition**);
- its `joint_public_key` and `verification_key` with the published transcript
  (the `dkg-transcript` output or the on-chain `GetDKGTranscript`). The relay
  sees every commitment and could show different commitments to different
  trustees; that comparison is what catches it.

`partial` and `sign-tally` repeat the verification-key check and refuse a
share that does not match the transcript.

### `aggregate`

Input:

```json
{"params": "<hex>", "dkg": "<hex>", "ballots": ["<hex Ballot>", "..."]}
```

The no-secrets view of a ballot set (see **Ballot sets**); an empty list is
allowed here and gives identity ciphertexts. Output, plus the ballot-set
fields:

```json
{"election_id": "live-2026",
 "contests": [{"contest_id": "president/alice", "pad": "<point>", "data": "<point>"}, "..."]}
```

`contests` follows `params.contest_ids` in order. No other op takes this
output as input.

### Ballot sets

Every op that takes `ballots` runs the auditor's per-ballot checks (shape,
every CDS proof, the selection proof, the credential presentation, the issuer
binding) on every record and checks nullifiers are unique, then sums the
ciphertexts per contest **itself**: no op takes an aggregate from its caller.
It refuses the whole set on any failing ballot (the error names it, e.g.
`ballot.cds_proof: ballot[1] ...`), a ballot of another election, or a
repeated nullifier. Every such op adds these fields to its output:

```json
{"ballot_count": 6,
 "ballots_digest": "<32-byte hex>",
 "ballots_fingerprint": "9C1D-0E2F-3A4B-5C6D-7E8F-9A0B-1C2D-3E4F",
 "ballots_by_position": {"president": 3, "secretary": 3}}
```

`ballots_digest` is order-independent, so the board, the console and every
trustee can compare it:

```
ballots_digest = SHA-256( "saksi.live.ballot-set.v1"
                          || u64be(len(election_id)) || election_id
                          || u64be(count)
                          || sorted( SHA-256(ballot_bytes_i) )... )
```

where `ballot_bytes_i` is each record's protobuf encoding (the bytes the
`ballots` hex decodes to). `ballots_fingerprint` is its first 16 bytes shown as
a fingerprint (see **Fingerprints**). `ballot_count` is also the upper bound every total is
decoded within.

### `partial`

Input:

```json
{"share_file": "/path/t2/share.json",
 "params": "<hex>", "dkg": "<hex>",
 "ballots": ["<hex Ballot>", "..."]}
```

Aggregates `ballots` itself after checking every record (see **Ballot sets**),
and refuses an empty list (`the ballot list is empty; refusing to decrypt or
sign an empty aggregate`). Refuses a share file of another election and a
share whose `s·G` is not the transcript's verification key for this trustee.
For each contest it calls `partial_decrypt_v2` (share point `s·pad` and a
Chaum-Pedersen proof over `(G, pad, vk, s·pad)` under the auditor's context
`u64be(16) || "saksi-auditor-v1" || u64be(len id) || trustee_id || u64be(len contest) || contest_id`),
then checks its own proof as the auditor will. Output, plus the ballot-set
fields:

```json
{"election_id": "live-2026", "trustee_id": "2",
 "partials": [{"contest_id": "president/alice", "partial": "<hex PartialDecryption>"}, "..."]}
```

Each `partial` is a `SubmitPartialDecryption(election_id, partial)` argument.
A trustee page should show `ballot_count` and `ballots_fingerprint` and
compare them with the board and the other trustees.

### `combine`

Input:

```json
{"params": "<hex>", "dkg": "<hex>",
 "ballots": ["<hex Ballot>", "..."],
 "partials": ["<hex PartialDecryption>", "..."]}
```

Aggregates `ballots` itself (see **Ballot sets**; an empty list is refused),
then runs the generator's combine (`decrypt_totals_bound`): every partial's
proof must verify against its trustee's verification key and this aggregate
(one failing proof fails the call), every contest needs at least `threshold`
distinct verified trustees, and each total must decode in
`[0, ballot_count]`. With fewer than `threshold` partials the error contains
`decryption.threshold`; partials made over a different ballot set fail with
`decryption.cp_proof`. Output, plus the ballot-set fields:

```json
{"election_id": "live-2026", "totals": [2, 1, 0, 1, 0, 2],
 "contests": [{"contest_id": "president/alice", "total": 2}, "..."]}
```

### `sign-tally`

Input:

```json
{"share_file": "/path/t2/share.json",
 "params": "<hex>", "dkg": "<hex>",
 "ballots": ["<hex Ballot>", "..."],
 "partials": ["<hex PartialDecryption>", "..."],
 "totals": [2, 1, 0, 1, 0, 2]}
```

Aggregates `ballots` itself (see **Ballot sets**; an empty list is refused),
re-runs `combine` over that aggregate and refuses if `totals` differ (`the
totals to sign ... differ from the totals the partials decrypt to ...`): a
trustee signs only totals it recomputed from ballot records it checked. Then
signs: a Schnorr proof of knowledge of its share under its verification key
over `"saksi.tally.sig.v1" || election_id || u64le(total)...`, the bytes
`PublishTally` verifies. Output, plus the ballot-set fields:

```json
{"election_id": "live-2026", "trustee_id": "2",
 "totals": [2, 1, 0, 1, 0, 2], "signature": "<64-byte hex>"}
```

## Verifier

### `verify-live`

The full audit over a live election's public record, with no generated
ground truth: the only difference from `audit-stream` is that the accuracy
comparison against a seeded answer key is not made. Input is exactly one of:

```json
{"record": {
   "params": "<hex>", "dkg": "<hex>", "issuer_public_key": "<point>",
   "ballots": ["<hex Ballot>", "..."],
   "partial_decryptions": ["<hex PartialDecryption>", "..."],
   "tally": "<hex TallyResult>",
   "expected_ballots": 6}}
```

```json
{"run_dir": "/path/runs/live-2026"}
```

`expected_ballots` is optional. When given (the chain's committed nullifier
count), a record holding a different number of ballots fails
`stream.completeness`, so an omitted ballot cannot pass unseen.

A `run_dir` holds `header.json` and `ballots.ndjson` in the `audit-stream`
layout (`params`, `dkg`, `issuer_pk`, `binding_context`, `partial_decryptions`,
`tally`, `ground_truth`, `voter_ids`, `positions`, `candidates`, `n`, plus the
optional `election_name` and `trustee_names`); `ground_truth` and `voter_ids`
may be empty and are ignored, `binding_context` must be the live one, and `n`
must equal the ballot lines (`stream.completeness`). A `ledger/ballots.ndjson`
dump, when present, adds the `ledger.order` check.

Output:

```json
{"overall": "pass",
 "summary": {"ballot_proofs": "pass", "nullifiers_unique": "pass",
             "partial_decryption_proofs": "pass", "totals_match_tally": "pass",
             "tally_signatures": "pass", "election_keys": "pass",
             "other_checks": "pass"},
 "checks": [{"check": "parameters.shape", "status": "pass", "passed": 1, "failed": 0,
             "detail": "election parameters shape is consistent"}, "..."],
 "failed_checks": [],
 "contests": [{"contest": "president/alice", "decoded": 2, "published_tally": 2}, "..."],
 "ballots": 6,
 "ballots_verified": {"total": 6, "by_position": {"president": 3, "secretary": 3}}}
```

- `checks`: every audit check id in first-seen order, with how many findings
  passed and failed and the first failure's detail (or the last pass's).
- `failed_checks`: the `checks` entries with a failed fatal finding.
- `summary` groups the check ids: `ballot_proofs` = `ballot.decode`,
  `ballot.shape`, `ballot.cds_proof`, `ballot.selection_sum`,
  `ballot.credential`, `ballot.issuer_binding`; `nullifiers_unique` =
  `nullifier.unique`; `partial_decryption_proofs` = `decryption.shape`,
  `decryption.duplicate`, `decryption.share_decode`, `decryption.cp_decode`,
  `decryption.cp_proof`, `decryption.threshold`; `totals_match_tally` =
  `tally.shape`, `tally.homomorphic_sum`, `tally.range`; `tally_signatures` =
  `tally.signatures`; `election_keys` = every `parameters.*`, `dkg.*` and
  `live.*` check. A group is `pass` only if at least one of its checks ran and
  none failed. `other_checks` covers everything else (`stream.completeness`,
  `ledger.order`, ...): it is `fail` iff a fatal check outside the other
  groups failed. So whenever `overall` is `fail`, at least one group is
  `fail`; a page that shows only the summary still cannot show all-pass for a
  failed audit. Read `overall` and `failed_checks` for the verdict.
- `contests[].decoded` is what threshold decryption of the recorded partials
  recovered (`null` if the combine could not run); `published_tally` is the
  tally's claim.
- `checks` also holds one live-only check, `live.joint_key_nonidentity`
  (fatal): it fails when the published joint key or any verification key is
  the identity point, because ElGamal under an identity key leaves every vote
  in the clear. The shared audit and the study's output do not have it; it is
  absent only when the transcript does not verify at all (then `dkg.*` fails).
- `ballots` counts the records read; `ballots_verified` counts those that
  passed every per-ballot check and were folded into the tally, in total and
  per `position_id`. It adds no check and changes none.
- `ledger_order` is present only for a `run_dir` with a ledger dump.

`verify-live` exits 0 whenever it produced a verdict, pass or fail; it exits 1
only when the input cannot be read.

## WebAssembly (phone)

`packages/saksi-wasm` is the phone's binding: a `wasm-bindgen` `cdylib` over
`saksi-live` that adds no cryptography of its own. `tools/live/build-wasm.sh`
builds it and writes the web package `packages/saksi-wasm/pkg/` (git-ignored),
named `@saksi/wasm`:

| File | What |
|---|---|
| `saksi_wasm_bg.wasm` | the module (release, `opt-level = "s"`, fat LTO, one codegen unit) |
| `saksi_wasm.js`, `saksi_wasm.d.ts` | `wasm-bindgen` glue for the `web` target: the string API below |
| `index.js`, `index.d.ts` | the typed wrapper the app imports: plain objects in and out |
| `wire.d.ts` | TypeScript types of every input and output shape below |
| `package.json` | `@saksi/wasm`, `type: module`, with the build's git revision |

It also writes `packages/saksi-wasm/pkg-node/` (the `nodejs` target, for the
tests). `wasm-bindgen-cli` is pinned to the crate's `wasm-bindgen` version
(`=0.2.130`) and installed into `tools/live/.tools/` (git-ignored) on the
first build.

### Calling convention (wasm)

- **Strings everywhere.** Every export takes one JS string, the JSON input
  shown below, and returns one JS string, the JSON output. `begin_issuance()`
  and `version()` take nothing. The typed wrapper (`index.js`) does the
  `JSON.stringify` and `JSON.parse`; `@saksi/wasm/raw` is the string API.
- **Errors** are thrown: a JS `Error` whose `message` is the CLI's error
  object, `{"error": "<message>"}`, with the same texts as the CLI ops.
  `errorOf(e)` returns the inner message. No secret appears in an error; a
  malformed input reports only its category and position.
- **Randomness** comes from the browser (`crypto.getRandomValues`, through
  `getrandom`'s `js` feature, enabled in this crate only).
- **Only voter functions are exported.** No issuer step (`issuer_presign`,
  `issuer_sign`) and nothing that rebuilds an issuer session.

Importing it from the app (Vite):

```ts
import init, { version, begin_issuance, build_ballot, errorOf } from "@saksi/wasm";
await init();            // fetches saksi_wasm_bg.wasm (Vite serves it as an asset)
console.info(version()); // {name, version, wire_format, protocol_wire_version, git_rev}
```

Vite should not pre-bundle it (`optimizeDeps: { exclude: ["@saksi/wasm"] }`),
so the glue's `new URL("saksi_wasm_bg.wasm", import.meta.url)` resolves to the
package file. `init({ module_or_path })` also takes the module bytes or a URL.

### Exports

#### `version()`

Output `{"name": "saksi-wasm", "version": "0.1.0", "wire_format":
"saksi-live-wire-v1", "protocol_wire_version": 1, "git_rev": "11c51c5"}`.
`wire_format` is `saksi_live::WIRE_FORMAT`, the version of this document's
format; `git_rev` is the saksi commit the build script built from (with
`-dirty` when the checkout had any uncommitted change outside ignored build
output), `null` when built without
the script. The app shows it and logs it.

#### `begin_issuance()`

The CLI `voter-begin` output: `{"blinded_commitment", "state": {"s_cred",
"b"}}`. Send `blinded_commitment` to the console (`issue-presign`); keep
`state` in memory for the next step.

#### `blind_challenge(input)`

The CLI `voter-blind` input and output: `{"state", "r", "issuer_public_key"}`
-> `{"e_prime", "state": {"s_cred", "r_prime", "alpha", "beta"}}`. Send
`e_prime` to the console (`issue-sign`); keep `state` for the next step.

#### `finalize_issuance(input)`

The CLI `voter-finalize` input and output: `{"state", "s_iss",
"issuer_public_key"}` -> `{"credential": {"s_cred", "signature_r",
"signature_s"}, "commitment"}`. Refuses a response that does not unblind into
a valid issuer signature.

#### `check_credential(input)`

Rebuilds a stored credential and checks it against the election's issuer key,
so the app can tell on start whether the credential in IndexedDB is usable
for this election. Input:

```json
{"params": "<hex ElectionParameters>",
 "credential": {"s_cred": "...", "signature_r": "...", "signature_s": "..."}}
```

Output `{"usable": true, "election_id", "issuer_public_key", "commitment"}`.
A credential the election's issuer did not sign is refused (thrown):
`the credential is not signed by this election's issuer`.

#### `election_info(input)`

Input `{"params": "<hex>", "dkg": "<hex DKGTranscript>"}`. Output:

```json
{"election_id": "live-2026",
 "positions": [{"id": "president", "candidates": ["alice", "bob", "carol"]}, "..."],
 "trustees": 5, "threshold": 3,
 "issuer_public_key": "<point>",
 "joint_public_key": "<point>",
 "joint_key_fingerprint": "7A1B-2C3D-4E5F-6071-8293-A4B5-C6D7-E8F9"}
```

Positions and candidates come from the contest ids, in ballot order. The
transcript is checked as `ballot` checks it (the election's, one dealer per
trustee, `t` commitments each, joint key not the identity).
`joint_key_fingerprint` is the value `dkg-transcript` and every trustee's
`dkg-receive` show: the phone shows it so people can confirm the ballots are
encrypted under the key the trustees made.

#### `build_ballot(input)`

Input: the CLI `ballot` input. Output: the CLI `ballot` output, plus
`opening`:

```json
{"ballot": "<hex Ballot: the SubmitBallot argument>",
 "election_id": "live-2026", "position_id": "president",
 "contest_ids": ["president/alice", "president/bob", "president/carol"],
 "nullifier": "<32-byte hex>", "tracking_code": "BC-7F3A-92C1",
 "ballot_fingerprint": "4F2A-91C3-07B8-D6E5-1A2B-3C4D-5E6F-7081",
 "opening": {"kind": "saksi-live-ballot-opening-v1",
             "ballot_digest": "<SHA-256 of the ballot bytes, hex>",
             "contest_ids": ["president/alice", "president/bob", "president/carol"],
             "choice": 1,
             "randomness": ["<scalar r_1>", "<scalar r_2>", "<scalar r_3>"]}}
```

It is `saksi_live::ballot::build_ballot_with_opening`: the same builder as the
CLI's `ballot`, which only copies each slot's ElGamal randomness out before
wiping it, so for the same random stream the ballot bytes are identical.
`opening` is opaque to the app: it hands it back to `benaloh_open` unchanged.
`ballot_fingerprint` (see the CLI `ballot`) names this ballot; the phone shows
it **before** the voter chooses cast or challenge, because that is what
commits the phone to this ballot. The tracking code does not: it is the same
for every ballot the voter builds for the position.

#### `benaloh_open(input)`

**A challenged ballot is a valid, submittable ballot** until a different
ballot with the same nullifier is recorded on the chain: whoever holds it can
submit it in the voter's place, and the opening tells them its vote. So the
challenged ballot and its opening (and these opened values) **never leave the
phone before the fresh ballot is on the chain**, and no server component, the
console above all, may accept or hold a challenged ballot.

Input `{"ballot": "<hex Ballot>", "opening": {...}}`. Refuses an opening made
for another ballot (`this opening is not for this ballot`, by
`ballot_digest`). Output, the opened values:

```json
{"election_id": "live-2026", "position_id": "president",
 "nullifier": "<32-byte hex>", "tracking_code": "BC-7F3A-92C1",
 "slots": [{"contest_id": "president/alice", "plaintext": 0, "randomness": "<scalar r_1>"},
           {"contest_id": "president/bob",   "plaintext": 1, "randomness": "<scalar r_2>"},
           {"contest_id": "president/carol", "plaintext": 0, "randomness": "<scalar r_3>"}]}
```

#### `benaloh_check(input)`

Input `{"params", "dkg", "ballot", "opened"}` with `opened` as above. Output
exactly as the CLI's `benaloh-check` (same function): `{"valid", "position_id",
"tracking_code", "ballot_fingerprint", "slots": [{"contest_id", "plaintext",
"reproduces"}], "encoded_choice", "encoded_candidate"}`. Each slot is re-encrypted under the
transcript's joint key with the revealed randomness,
`(r·G, m·G + r·Y)`, and compared with the ballot's `(pad, data)`. `valid` is
true iff every slot reproduces and exactly one slot holds 1; then
`encoded_candidate` is the candidate id the ballot encodes. **The app
compares `position_id` and `encoded_candidate` with the position and the
candidate the voter chose**, and `ballot_fingerprint` (the fingerprint of the
ballot actually checked) with the one it showed before the challenge, and
shows all three side by side.

#### `tracking_code(input)`

Input `{"nullifier": "<hex>"}`, output `{"tracking_code": "BC-XXXX-XXXX"}`
(the board's `formatTrackingCode`).

### The Benaloh challenge

1. The phone builds the ballot (`build_ballot`) and shows the voter its
   **`ballot_fingerprint`**, before asking cast or challenge. That commits the
   phone to this ballot; the tracking code, shared by every ballot the voter
   builds for the position, would not.
2. The voter chooses **cast** or **challenge**.
   - **Cast:** the app submits `ballot` and drops `opening`. The board shows
     the recorded ballot's fingerprint next to its tracking code; the voter
     can see it is the one the phone showed.
   - **Challenge:** the app calls `benaloh_open`, then `benaloh_check`, and
     shows the slots, `valid`, `position_id`, `encoded_candidate` and the
     checked `ballot_fingerprint` next to the voter's position, choice and the
     fingerprint shown in step 1.
3. **A challenged ballot is never submitted, and never leaves the phone**
   until the fresh ballot is recorded. Until then it is a valid ballot
   carrying the voter's nullifier: anyone holding it could submit it in place
   of the voter's real ballot, and the chain would take it (first use of the
   nullifier) and refuse the real one. No server component may accept or hold
   one. The app discards the ballot, the opening and the opened values, and
   builds a fresh ballot (`build_ballot` again), which draws fresh randomness
   and so has a new fingerprint. The voter may challenge again or cast.
   Checking the opened values elsewhere (`saksi-demo live benaloh-check`, or a
   second device) is for after the fresh ballot is on the chain, offline.

The fresh ballot has **the same nullifier**, and so the same tracking code,
as the challenged one, but a different ballot fingerprint. The nullifier is a function of the credential, the
election and the position: one per voter per position, so a voter cannot
cast twice in a position. That is fine for the challenge because the
challenged ballot never reaches the chain; the chain sees the nullifier once,
on the cast ballot. (Were a challenged ballot submitted by mistake, the
chaincode would accept it, since it is a valid ballot, and then refuse the
cast one at the `nullifier` gate; the Go test shows that order the other way
round.) It also means an opening links the challenged choice to the voter's
tracking code, which is one more reason the opened values stay on the phone.

The check is only as independent as the code that runs it: a phone whose
wasm lied could lie in its check too. The demo runs both in the same wasm, to
show the mechanism; the honest version checks the opened values elsewhere,
after the fresh ballot is recorded (step 3).

### What the phone keeps, and what it drops

| Value | Secret? | The app |
|---|---|---|
| `begin_issuance().state` | yes (`s_cred`, `b`) | keeps in memory for `blind_challenge`, then drops |
| `blind_challenge().state` | yes (`s_cred`, `α`, `β`) | keeps in memory for `finalize_issuance`, then drops |
| `finalize_issuance().credential` | yes (`s_cred` votes) | **the one value it stores** (IndexedDB); never sent to the console |
| `build_ballot().opening` | yes (reveals the vote) | memory only; dropped once the ballot is cast or opened |
| `benaloh_open()` output | reveals the challenged vote | shown, then dropped with the challenged ballot |
| `blinded_commitment`, `e_prime`, the cast `ballot`, `nullifier`, `tracking_code`, `ballot_fingerprint` | no | sent to the console or shown |
| a challenged `ballot` | not secret, but submittable | never leaves the phone before the fresh ballot is recorded; then dropped |

The app must never log the inputs or outputs of these exports. Inside the
crate, every input string is wiped once parsed, every output is serialised
into an exactly-sized buffer that is wiped once copied into the JS string,
and the voter-state, credential, opening and opened-value structs wipe their
strings on drop. JavaScript strings cannot be wiped: dropping every reference
promptly is all the app can do.

## Chaincode acceptance

The artifacts above pass the chaincode at `0cdc335` unchanged.
`TestLiveArtifactsPassTheChaincode` feeds the CLI-produced fixture
`packages/saksi-protocol/test-vectors/live-v1/election.json` (schema tag
`saksi-live-chaincode-fixture-v1`) through `CreateElection`,
`PublishDKGTranscript`, six `SubmitBallot`s, `CloseElection`, eighteen
`SubmitPartialDecryption`s and `PublishTally`, and checks the refusals: a
ballot with one changed CDS byte (gate `cds`), the same ballot twice (gate
`nullifier`), and a tally with two signatures (`tally has 2 valid trustee
signatures, threshold is 3`).

The Rust test `committed_chaincode_fixture_is_current` fails when the fixture
is stale (wrong schema tag, or its record no longer passes `verify-live`), and
both tests' failure messages point to the regenerate script:

```
tools/live/regen-chaincode-fixture.sh
```

The phone's ballots are held to the same standard. `tools/live/test-wasm.sh`
runs `@saksi/wasm` under node against the CLI as issuer and trustees, writes a
fixture of that election (two ballots built in wasm, four by the CLI, a
challenged wasm ballot), and runs `TestWasmBuiltBallotsPassTheChaincode` over
it: the wasm ballots are submitted first and accepted, a wasm ballot with one
changed CDS byte is refused at gate `cds`, the challenged ballot is refused at
gate `nullifier` once the cast one is recorded, and the 3-signature tally is
published with the expected totals. The committed copy
`packages/saksi-protocol/test-vectors/live-v1/wasm-election.json` (schema
`saksi-live-wasm-fixture-v1`) lets `go test ./...` run that test without node;
`committed_wasm_fixture_is_current` fails when it is stale. Regenerate it
with:

```
tools/live/test-wasm.sh --write-fixture
```
