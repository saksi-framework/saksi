#!/usr/bin/env bash
# Builds packages/saksi-wasm for the phone and writes the ready-to-import web
# package packages/saksi-wasm/pkg/ (git-ignored), named @saksi/wasm:
#
#   saksi_wasm_bg.wasm   the module
#   saksi_wasm.js/.d.ts  wasm-bindgen's glue for the `web` target (string API)
#   index.js/.d.ts       the typed wrapper the app imports (JSON in and out)
#   wire.d.ts            TypeScript types of every input and output shape
#   package.json
#
# and packages/saksi-wasm/pkg-node/ (wasm-bindgen's `nodejs` target, for the
# tests). Prints the raw and gzip sizes.
#
# The release build is size-optimised (opt-level "s", fat LTO, one codegen
# unit) through CARGO_PROFILE_RELEASE_* for this invocation only, in its own
# target dir (target/wasm), so the workspace's release profile and every
# other crate's build are unchanged.
#
# Needs a rustup toolchain with wasm32-unknown-unknown. On the Mac, Homebrew
# cargo lacks the target; this script puts rustup's first on PATH when it is
# there. wasm-bindgen-cli is installed at the pinned version into
# tools/live/.tools (git-ignored) on first run.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -d /opt/homebrew/opt/rustup/bin ]; then
  export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
fi
WASM_BINDGEN_VERSION=0.2.130
tools="$repo/tools/live/.tools"
bindgen="$tools/bin/wasm-bindgen"
crate="$repo/packages/saksi-wasm"
target_dir="$repo/target/wasm"

if ! [ -x "$bindgen" ] || [ "$("$bindgen" --version)" != "wasm-bindgen $WASM_BINDGEN_VERSION" ]; then
  echo "installing wasm-bindgen-cli $WASM_BINDGEN_VERSION into tools/live/.tools ..."
  cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION" --locked --root "$tools" 2>&1 | tail -2
fi
if ! grep -q "wasm-bindgen = \"=$WASM_BINDGEN_VERSION\"" "$crate/Cargo.toml"; then
  echo "packages/saksi-wasm/Cargo.toml must pin wasm-bindgen = \"=$WASM_BINDGEN_VERSION\"" >&2
  exit 1
fi

git_rev="$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$(git -C "$repo" status --porcelain -- packages 2>/dev/null)" ]; then
  git_rev="$git_rev-dirty"
fi

start=$(date +%s)
(
  cd "$repo"
  SAKSI_WASM_GIT_REV="$git_rev" \
  CARGO_TARGET_DIR="$target_dir" \
  CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
  CARGO_PROFILE_RELEASE_LTO=fat \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  CARGO_PROFILE_RELEASE_DEBUG=false \
  CARGO_PROFILE_RELEASE_STRIP=debuginfo \
    cargo build -p saksi-wasm --release --target wasm32-unknown-unknown 2>&1 | tail -2
)
echo "cargo build: $(( $(date +%s) - start )) s"
raw="$target_dir/wasm32-unknown-unknown/release/saksi_wasm.wasm"

rm -rf "$crate/pkg" "$crate/pkg-node"
"$bindgen" --target web --out-dir "$crate/pkg" "$raw"
"$bindgen" --target nodejs --out-dir "$crate/pkg-node" "$raw"
cp "$crate/js/index.js" "$crate/js/index.d.ts" "$crate/js/wire.d.ts" "$crate/pkg/"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$crate/Cargo.toml" | head -1)"
sed -e "s/@VERSION@/$version/" -e "s/@GIT_REV@/$git_rev/" "$crate/js/package.json.in" > "$crate/pkg/package.json"
printf '{"name":"@saksi/wasm-node","private":true,"main":"saksi_wasm.js","types":"saksi_wasm.d.ts"}\n' > "$crate/pkg-node/package.json"

size() { wc -c < "$1" | tr -d ' '; }
gz() { gzip -9 -c "$1" | wc -c | tr -d ' '; }
wasm="$crate/pkg/saksi_wasm_bg.wasm"
echo "saksi-wasm $version ($git_rev), wire format $(sed -n 's/.*WIRE_FORMAT: &str = "\(.*\)";/\1/p' "$repo/packages/saksi-live/src/lib.rs")"
printf '%-32s %10s %10s\n' artifact bytes gzip-9
printf '%-32s %10s %10s\n' "cargo saksi_wasm.wasm" "$(size "$raw")" "$(gz "$raw")"
printf '%-32s %10s %10s\n' "pkg/saksi_wasm_bg.wasm" "$(size "$wasm")" "$(gz "$wasm")"
printf '%-32s %10s %10s\n' "pkg/saksi_wasm.js" "$(size "$crate/pkg/saksi_wasm.js")" "$(gz "$crate/pkg/saksi_wasm.js")"
printf '%-32s %10s %10s\n' "pkg/index.js" "$(size "$crate/pkg/index.js")" "$(gz "$crate/pkg/index.js")"
echo "wrote packages/saksi-wasm/pkg (web, @saksi/wasm) and packages/saksi-wasm/pkg-node (nodejs)"
