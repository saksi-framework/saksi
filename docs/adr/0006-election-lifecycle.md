# ADR-0006: Election Lifecycle and Bulletin-Board Transactions

## Status

Accepted

## Context

The bulletin board began with only `SubmitBallot` / `GetBallot`. A complete
election needs a defined lifecycle: parameters must be fixed before voting, the
distributed key must be published, voting must be closeable, trustees must post
decryption shares only after closing, and a final tally must be published. These
states and transitions must be enforced on-chain so that, for example, a ballot
cannot be cast after the poll closes and a decryption share cannot be posted
while voting is still open.

We also need each stored object to be **self-describing** rather than relying on
positional conventions between the writer (SDK) and the reader (auditor), so the
two can evolve independently and an auditor can route data without out-of-band
layout knowledge.

## Decision

Model an election as a small state machine keyed by `election_id`, with one
lifecycle status value (`open` → `closed`) and a set of chaincode transactions:

| Transaction | Phase | Precondition | Effect |
| --- | --- | --- | --- |
| `CreateElection` | setup | election id is new | store `ElectionParameters`; status `open` |
| `PublishDKGTranscript` | setup | election exists; threshold + trustee count match params; none published yet | store the `DKGTranscript` (one per election) |
| `SubmitBallot` | voting | election exists and is `open`; checks per ADR-0005; nullifier unused | store the ballot; mark the nullifier spent |
| `CloseElection` | close | election exists and is `open` | status → `closed` |
| `SubmitPartialDecryption` | tally | election `closed`; contest_id and trustee_id ∈ params; share shaped; proof present; no prior share for (contest, trustee) | store the share |
| `PublishTally` | tally | election `closed`; one total per contest; none published yet | store the `TallyResult` (one per election) |

Each kind has a matching query (`GetElection`, `GetDKGTranscript`, `GetBallot`,
`GetElectionStatus`, `GetPartialDecryption`, `GetTally`). State is keyed by
composite keys (`election`, `dkg`, `status`, `ballot`, `nullifier`, `partialdec`,
`tally`).

Stored decryption shares carry their own `contest_id` (added to the
`PartialDecryption` wire message) so they are self-describing; the auditor routes
each share to its contest by id rather than assuming a contest-major positional
layout.

Per ADR-0005, the chaincode performs only cheap, deterministic checks plus
credential-signature verification and the uniqueness guards (nullifier; one share
per contest+trustee). The heavy NIZKs attached to ballots and shares are recorded
but verified off-chain by the auditor.

## Consequences

- Lifecycle ordering is enforced on-chain: no ballots after close, no decryption
  shares before close, exactly one DKG transcript and one tally per election.
- The `contest_id` on `PartialDecryption` removes a fragile positional contract
  between the SDK and the auditor; shares may be submitted in any order and a
  contest needs only `≥ threshold` distinct verified trustees.
- The lifecycle is intentionally minimal for the one-election demo: there is no
  re-opening, no per-voter eligibility roster on-chain (eligibility is the
  credential), and no scheduled open/close times. These are additive later
  without breaking the existing transactions or queries.
- The transaction surface and state keys are now an interface other components
  depend on (SDK, auditor, e2e driver); changing a key or a precondition is a
  breaking change and should be recorded in a follow-up ADR.
