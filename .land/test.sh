#!/bin/sh
# The tests leg of .land/gates.sh, run the way upstream's justfile runs test-hiqlite: the
# integration tests under src/bin/tests talk to a live test backend on localhost:8081, so this
# builds the server, starts it in test mode on a fresh hiqlite data directory, waits until it
# answers its ping, runs the whole workspace's tests against it, and stops it whatever happened.
# Port 8081 already in use is refused by name before anything starts, because the tests would
# then talk to a server this leg did not start. A backend that exits before it answers is
# refused by name with the tail of its log. Runs from the repository root in a fresh clone.
set -u
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)" || exit 2

for tool in curl lsof; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "refused: tool_missing $tool. The tests leg needs it to reach the test backend on this host."
    exit 1
  fi
done
if lsof -nP -iTCP:8081 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "refused: port_busy 8081. Something already listens there, and the integration tests would talk to it instead of this tree's backend. Run this leg when that process has stopped:"
  lsof -nP -iTCP:8081 -sTCP:LISTEN
  exit 1
fi

cargo build || exit 1
# The gate may build into its own target directory, so the binary is found where cargo put it.
target_dir=$(cargo metadata --format-version 1 --no-deps | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
if [ -z "$target_dir" ] || [ ! -x "$target_dir/debug/rauthy" ]; then
  echo "refused: binary_missing. cargo build finished but no rauthy binary is at '$target_dir/debug/rauthy'."
  exit 1
fi

mkdir -p data
rm -rf data/logs data/logs_cache data/state_machine data/state_machine_cache
backend_log=$(mktemp)
PUB_URL=localhost:8081 RP_ORIGIN=http://localhost:8081 "$target_dir/debug/rauthy" serve -c config-test.toml --test >"$backend_log" 2>&1 &
backend=$!
stop_backend() {
  kill "$backend" 2>/dev/null
  wait "$backend" 2>/dev/null
}
trap stop_backend EXIT

until curl -fs localhost:8081/auth/v1/ping >/dev/null 2>&1; do
  if ! kill -0 "$backend" 2>/dev/null; then
    echo "refused: backend_exited. The test backend stopped before it answered its ping, so no test ran. The end of its log:"
    tail -n 40 "$backend_log"
    exit 1
  fi
  sleep 1
done

cargo test --workspace --no-fail-fast
