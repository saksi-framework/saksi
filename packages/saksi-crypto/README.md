# saksi-crypto

Cryptographic primitives for the Saksi framework over the ristretto255 prime-order group.

This crate is currently an **empty skeleton** — only the workspace wiring and conventions are in place. Each primitive lands in its own pull request closing the issue listed below.

| Primitive | Issue |
|---|---|
| ElGamal encryption | [#10](https://github.com/saksi-framework/balotachain/issues/10) |
| Pedersen distributed key generation | [#11](https://github.com/saksi-framework/balotachain/issues/11) |
| Threshold decryption | [#12](https://github.com/saksi-framework/balotachain/issues/12) |
| Chaum-Pedersen NIZK (equality of discrete logs) | [#13](https://github.com/saksi-framework/balotachain/issues/13) |
| CDS OR proof (ballot well-formedness) | [#14](https://github.com/saksi-framework/balotachain/issues/14) |
| Pedersen commitments | [#15](https://github.com/saksi-framework/balotachain/issues/15) |
| Benaloh challenge | [#16](https://github.com/saksi-framework/balotachain/issues/16) |

## Conventions

- **Group:** ristretto255 via [`curve25519-dalek`](https://docs.rs/curve25519-dalek). No other group is acceptable in this crate.
- **Transcripts:** all Fiat-Shamir conversions use [`merlin`](https://docs.rs/merlin) with explicit, documented domain-separation labels.
- **Constant time:** secret-dependent branches and comparisons go through [`subtle`](https://docs.rs/subtle). Secret material zeroizes on drop via [`zeroize`](https://docs.rs/zeroize).
- **Unsafe:** forbidden at the crate level.
- **Testing:** property-based tests via [`proptest`](https://docs.rs/proptest); each primitive ships positive, negative, and randomized cases.

## Out of scope

- Anonymous credentials — see [`saksi-credentials`](../saksi-credentials/).
- Wire formats — see [`saksi-protocol`](../saksi-protocol/).
- Pairing-friendly groups (BLS12-381). The architecture commits to ristretto255 only; no pairings.
