#!/bin/sh
# The ui leg of .land/gates.sh: builds the wasm modules and the frontend into templates/html and
# static/v1, the same steps upstream's justfile runs as build-wasm and build-ui, because the askama
# templates the server compiles are generated there and the cargo legs cannot build without them.
# Each tool it needs is checked first; a missing one is refused by name with what to install.
# Runs from the repository root in a fresh clone.
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 2

missing=0
need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "refused: tool_missing $1. The ui leg builds the frontend templates the cargo legs compile, and it needs $1 on this host: $2"
    missing=1
  fi
}
need wasm-pack "install it with cargo install wasm-pack."
need npm "install Node.js 22, which carries npm."
need rustup "install rustup, which adds the wasm32-unknown-unknown target."
if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
  echo "refused: target_missing wasm32-unknown-unknown. The ui leg compiles the wasm modules for that target: add it with rustup target add wasm32-unknown-unknown."
  missing=1
fi
[ "$missing" -eq 0 ] || exit 1

set -e
rm -rf frontend/src/wasm templates/html static/v1
mkdir -p templates/html static/v1
(
  cd src/wasm-modules
  wasm-pack build -d ../../frontend/src/wasm/spow --no-pack --out-name spow --features spow
  wasm-pack build -d ../../frontend/src/wasm/md --no-pack --out-name md --features md
)
(
  cd frontend
  npm ci
  npm run build
)
