#!/usr/bin/env bash
# Proves packages/saksi-live compiles and links for wasm32-unknown-unknown.
#
# A throwaway consumer crate (outside the workspace) depends on saksi-live and
# turns on getrandom/js, as packages/saksi-wasm does. saksi-live itself
# does not enable it, so native builds are unchanged.
#
# Needs a rustup toolchain with the wasm32-unknown-unknown target. On the Mac:
#   PATH=/opt/homebrew/opt/rustup/bin:$PATH tools/live/wasm-check.sh
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
dir="$(mktemp -d "${TMPDIR:-/tmp}/saksi-live-wasm-check.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir/src"
cat > "$dir/Cargo.toml" <<TOML
[package]
name = "saksi-live-wasm-check"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
saksi-live = { path = "$repo/packages/saksi-live" }
getrandom = { version = "0.2", features = ["js"] }
rand_core = { version = "0.6", features = ["getrandom"] }

[workspace]
TOML
cat > "$dir/src/lib.rs" <<'RS'
//! Links every voter-side entry point the phone will call.
use rand_core::OsRng;
use saksi_live::{ballot, election, issuance};

#[no_mangle]
pub extern "C" fn check() -> usize {
    let begin = issuance::voter_begin(&mut OsRng);
    let blind = issuance::voter_blind(
        &issuance::BlindRequestJson {
            state: begin.state.clone(),
            r: begin.blinded_commitment.clone(),
            issuer_public_key: begin.blinded_commitment.clone(),
        },
        &mut OsRng,
    );
    let fin = blind.as_ref().ok().map(|b| {
        issuance::voter_finalize(&issuance::FinalizeRequest {
            state: b.state.clone(),
            s_iss: b.e_prime.clone(),
            issuer_public_key: begin.blinded_commitment.clone(),
        })
    });
    let ballot = fin.and_then(|f| f.ok()).map(|f| {
        ballot::build_ballot(
            &ballot::BallotRequest {
                params: String::new(),
                dkg: String::new(),
                credential: f.credential,
                position_id: "p".into(),
                choice: 0,
            },
            &mut OsRng,
        )
    });
    election::tracking_code(&[0u8; 32]).len() + usize::from(ballot.is_some())
}
RS
cd "$dir"
cargo build --release --target wasm32-unknown-unknown 2>&1 | tail -3
ls -l "$dir/target/wasm32-unknown-unknown/release/saksi_live_wasm_check.wasm"
echo "saksi-live: wasm32-unknown-unknown build OK"
