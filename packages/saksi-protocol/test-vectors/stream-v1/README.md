# stream-v1 — cross-language NDJSON format fixture

Pins the **format contract** of the streamed election artifact
(`header.json` + `ballots.ndjson`) that the Rust generator writes and the Go
campaign runner reads. Field names, types, and the line-delimited ballot layout
are the contract; drift on either side must fail a test, not a campaign.

## What this is NOT

Not a crypto golden vector. The generator uses `OsRng`, so real ballot bytes
differ every run and cannot be byte-pinned. The hex payloads here are **static
placeholders** chosen only to be valid hex — never decode them as real ballots
or compare them against generated output.

Byte-exact cross-language crypto agreement is pinned separately by
`ballot-v1.hex`, `credential-sig-v1.hex`, and `cds-proof-v1.hex`.

## Consumers

- Rust: `saksi-auditor/src/stream.rs` (`fixture_parses_with_the_same_reader`)
- Go: the campaign runner's header/ndjson reader (Phase 3)

Both parse *this* directory. Adding, renaming, or retyping a header field
without updating both readers breaks one of those tests.
