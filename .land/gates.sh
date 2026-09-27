#!/bin/sh
# The gates this fork runs before any commit, the same legs docs/design/project.json declares.
# repo_land runs this file as the whole gate when it stands here. Every leg runs even after a
# red one, so the log covers all of them; the exit status is red if any leg was.
set -u
status=0
leg() {
  echo "--- $* ---"
  "$@"
  code=$?
  echo "--- status $code: $* ---"
  [ "$code" -eq 0 ] || status=1
}
leg sh scripts/design/gate.sh
leg sh .land/ui.sh
leg cargo fmt --all
leg cargo clippy --workspace --all-targets -- -D warnings
leg sh .land/test.sh
exit "$status"
