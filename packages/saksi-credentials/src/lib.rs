//! # saksi-credentials
//!
//! Anonymous voter credentials on ristretto255 — no pairings.
//!
//! ## Construction
//!
//! - **Issuance (B1):** Pointcheval-Stern blind-Schnorr. The voter holds a
//!   secret scalar `s_cred` and commits to it as `C = s_cred · G`. The
//!   issuer (election authority) holds a long-term Schnorr key
//!   `(x_i, Pk_i)`. After the three-flow protocol implemented in
//!   [`issuance`], the voter ends up with a signature `(R', s_sig)` on `C`
//!   under `Pk_i` such that the issuer cannot link the final credential
//!   back to the request it signed.
//!
//! - **Presentation (B2):** [`presentation`] emits a
//!   [`saksi_protocol::CredentialPresentation`] whose `presentation_proof`
//!   bytes pack the issuer Schnorr signature `(R', s_sig)` followed by a
//!   Chaum-Pedersen NIZK proving `C = s_cred · G ∧ nullifier = s_cred · H_e`.
//!   The verifier checks both. `H_e = nullifier_h(election_id)` is a
//!   per-election hash-to-point in [`nullifier`].
//!
//! - **Nullifier (B2):** [`nullifier::derive_nullifier`] is a deterministic
//!   PRF: same `(s_cred, election_id)` ⇒ same 32-byte value, so the
//!   bulletin board can detect double-voting by byte equality; different
//!   `election_id` ⇒ unlinkable nullifiers.
//!
//! ## Threat model
//!
//! - **Unlinkability between issuance and presentation:** the holder is
//!   the only party that can correlate the issuer-side handle
//!   (`C' = C + b · G`, plus the `(R, e', s_iss)` transcript) with the
//!   final published `(C, R', s_sig)`. Both `b` and the
//!   re-randomization factors `(α, β)` are sampled uniformly and never
//!   revealed.
//!
//! - **Cross-presentation linkability:** the holder reveals `C` directly
//!   at presentation time, so two presentations of the *same* credential
//!   are linkable to each other. Single-ballot-per-election is enforced
//!   by the nullifier; cross-presentation unlinkability is out of scope
//!   for the demo and would require additional commitment re-randomization
//!   or a structure-preserving signature scheme (BBS+, PS).
//!
//! - **Proof stubs upstream:** the Wave 1 modules used here
//!   (`saksi_crypto::nizk::schnorr`, `saksi_crypto::nizk::chaum_pedersen`)
//!   are full implementations, not stubs. This crate does not introduce
//!   any new stubs.
//!
//! ## Constant-time and zeroize discipline
//!
//! All types that own secret material — `IssuerSecretKey`, `Credential`,
//! `VoterBlindState`, `VoterFinalizeState`, `IssuerSession` — zeroize on
//! drop and intentionally omit `Debug`. All scalar arithmetic uses the
//! constant-time operations from `curve25519-dalek`. The verifier path
//! is variable-time over public inputs only.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod issuance;
pub mod nullifier;
pub mod presentation;

pub use issuance::{
    issuer_pre_sign, issuer_sign, voter_begin_issuance, voter_blind_challenge,
    voter_finalize_issuance, BlindRequest, BlindedChallenge, Credential, IssuerPreSignature,
    IssuerPublicKey, IssuerResponse, IssuerSecretKey, IssuerSession, VoterBlindState,
    VoterFinalizeState,
};
pub use nullifier::{
    compress_nullifier, decompress_nullifier, derive_nullifier, nullifier_h, NULLIFIER_DOMAIN,
};
pub use presentation::{presentation_context, verify_presentation};
