#!/bin/sh
# Own the isolated Linux builder and PostgreSQL identity store for this exact-source gate.
# Hiqlite remains Rauthy's cache only. No host port or live database is used.
set -eu
if command -v docker >/dev/null 2>&1; then
    docker=$(command -v docker)
elif [ -x /usr/local/bin/docker ]; then
    docker=/usr/local/bin/docker
else
    echo 'refused: docker_missing; the fork gate requires an isolated PostgreSQL container' >&2
    exit 1
fi
image=sha256:4204b8d967c2ec3adf4a2cfc3bcf1b9aeab1d6a876b7ca782ef3d2a68284036a
"$docker" image inspect "$image" >/dev/null
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
name="rauthy-pg-gate-$(git -C "$root" rev-parse --short=12 HEAD)-$$"
target="${CARGO_TARGET_DIR:?The gate venue must supply its owned target directory}/rauthy-linux"
mkdir -p "$target"
target=$(CDPATH= cd -- "$target" && pwd -P)
network_created=false
postgres_created=false
builder_created=false
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ "$builder_created" = true ]; then
        "$docker" rm -f "$name" >/dev/null || result=1
    fi
    if [ "$postgres_created" = true ]; then
        "$docker" rm -f "$name-pg" >/dev/null || result=1
    fi
    if [ "$network_created" = true ]; then
        "$docker" network rm "$name" >/dev/null || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
"$docker" network create "$name" >/dev/null
network_created=true
"$docker" create --name "$name-pg" --network "$name" \
    -e POSTGRES_USER=rauthy -e POSTGRES_PASSWORD=123SuperSafe -e POSTGRES_DB=rauthy \
    postgres:17.11-bookworm >/dev/null
postgres_created=true
"$docker" start "$name-pg" >/dev/null
until "$docker" exec "$name-pg" pg_isready -U rauthy -d rauthy >/dev/null; do
    if [ "$("$docker" inspect --format '{{.State.Running}}' "$name-pg")" != true ]; then
        "$docker" logs "$name-pg" >&2
        echo 'refused: postgres_exited before readiness' >&2
        exit 1
    fi
    sleep 1
done
"$docker" create --name "$name" --network "$name" \
    --mount "type=bind,src=$root,dst=/work" \
    --mount "type=bind,src=$target,dst=/target" \
    -e CARGO_TARGET_DIR=/target -e HIQLITE=false -e PG_HOST="$name-pg" \
    -e PG_PORT=5432 -e PG_DB_NAME=rauthy -e PG_USER=rauthy -e PG_PASSWORD=123SuperSafe \
    -e IDENTITY_TEST_DATABASE_URL="host=$name-pg port=5432 user=rauthy password=123SuperSafe dbname=rauthy" \
    -w /work "$image" sh .land/identity-link-gate.sh >/dev/null
builder_created=true
"$docker" start -a "$name"
result=$("$docker" inspect --format '{{.State.ExitCode}}' "$name")
exit "$result"
