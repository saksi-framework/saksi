# saksi-credentials

Anonymous credentials on ristretto255 for BalotaChain voters.

**Status:** empty skeleton. Implementation in issues [#18](https://github.com/saksi-framework/balotachain/issues/18) (scaffold + blind issuance) and [#19](https://github.com/saksi-framework/balotachain/issues/19) (presentation NIZK + nullifier derivation).

## Role in the system

At registration the voter authenticates to the registrar via any of the pluggable bootstrap methods (WMSU SSO, Student-ID lookup, in-person QR). The registrar blind-signs a commitment the voter prepared from a freshly sampled secret. The voter unblinds the signature locally into a credential held on the device.

At cast time the voter presents a re-randomized form of the credential along with a Schnorr non-interactive zero-knowledge proof that they know its opening, and emits a deterministic nullifier `N = H(credential_secret || election_id)`. The chaincode rejects any submission whose nullifier is already on the bulletin board for the same election, which prevents double-voting without ever linking the credential to the voter's real identity.

## Scheme choice

Blind-signature variant on ristretto255 (no pairings). The exact scheme — likely a blind Schnorr variant with care taken to avoid the one-more-forgery attack — is decided in issue #18 and recorded in an ADR.

Other approaches (BBS+ / Coconut over BLS12-381) are explicitly **out of scope**. The locked architecture commits to a single ristretto255 group across all of Saksi.
