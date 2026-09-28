#!/bin/sh
# Build the real browser and test the fork with PostgreSQL as its only identity datastore.
set -eu
export HIQLITE=false PUB_URL=localhost:8081 RP_ORIGIN=http://localhost:8081
sh scripts/design/gate.sh
cargo fmt --all -- --check
(cd src/wasm-modules && wasm-pack build -d ../../frontend/src/wasm/spow --no-pack --out-name spow --features spow)
(cd src/wasm-modules && wasm-pack build -d ../../frontend/src/wasm/md --no-pack --out-name md --features md)
(cd frontend && npm ci && npm run check && npm run format-check && npm run build)
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace
HQL_DATA_DIR=$(mktemp -d)
export HQL_DATA_DIR
log=/target/identity-link-postgres-backend.log
/target/debug/rauthy serve -c config-test.toml --test >"$log" 2>&1 &
server=$!
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if kill -0 "$server" 2>/dev/null; then
        kill -TERM "$server" || result=1
    fi
    wait "$server" || {
        ended=$?
        if [ "$ended" -ne 143 ]; then result=1; fi
    }
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# The HTTP backend exposes no readiness subscription; an exited child refuses by name.
until curl --fail --silent http://localhost:8081/auth/v1/ping >/dev/null; do
    if ! kill -0 "$server" 2>/dev/null; then
        cat "$log" >&2
        echo 'refused: test_backend_exited before readiness' >&2
        exit 1
    fi
    sleep 1
done
cargo test --locked --workspace --no-fail-fast
