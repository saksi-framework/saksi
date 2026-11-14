//! # saksi-live
//!
//! The party-side steps of a live election, as I/O-free functions whose
//! inputs and outputs are the hex/JSON wire format of `docs/live/wire-format.md`:
//!
//! - [`election`]: election parameters, the joint key read from a published
//!   DKG transcript, the tracking code.
//! - [`issuance`]: the voter's three and the issuer's two blind-issuance steps.
//! - [`ballot`]: one position's ballot record (presentation, ElGamal, CDS,
//!   selection proof).
//! - [`dkg`]: one trustee's deal and receive, with shares masked for the
//!   relay.
//!
//! Everything here compiles for `wasm32-unknown-unknown` (the phone's
//! WebAssembly calls [`issuance`] and [`ballot`] directly); the consumer turns
//! on `getrandom/js`. The `saksi-demo live` CLI adds the file handling.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ballot;
pub mod codec;
pub mod dkg;
pub mod election;
pub mod issuance;
