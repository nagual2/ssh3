#!/usr/bin/env bash
# Generate the many-small-files payload (B8): 1000×4 KiB + 100×100 KiB random
# files plus a sorted sha256 manifest, in tmpfs. Idempotent.
# Env overrides: SMALL_COUNT, SMALL_SIZE_KB, LARGE_COUNT, LARGE_SIZE_KB, MANY_DIR
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

SMALL_COUNT="${SMALL_COUNT:-1000}"
SMALL_SIZE_KB="${SMALL_SIZE_KB:-4}"
LARGE_COUNT="${LARGE_COUNT:-100}"
LARGE_SIZE_KB="${LARGE_SIZE_KB:-100}"
MANY_DIR="${MANY_DIR:-/dev/shm/ssh3-manyfiles}"
FILES_DIR="$MANY_DIR/files"
MANIFEST="$MANY_DIR/manifest.sha"

case "${1:-}" in
--clean)
    rm -rf "$MANY_DIR"
    echo "cleaned: $MANY_DIR"
    exit 0
    ;;
esac

compute_manifest() {
    (cd "$MANY_DIR" && find files -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)
}

mkdir -p "$FILES_DIR"
if [ -f "$MANIFEST" ] && diff -q <(compute_manifest) "$MANIFEST" >/dev/null 2>&1; then
    bench::log "manyfiles payload OK: $MANY_DIR"
else
    bench::log "generating manyfiles payload in $MANY_DIR..."
    rm -rf "$FILES_DIR"
    mkdir -p "$FILES_DIR"
    i=1
    while [ "$i" -le "$SMALL_COUNT" ]; do
        dd if=/dev/urandom of="$FILES_DIR/f_small_$i.bin" bs=1024 count="$SMALL_SIZE_KB" status=none
        i=$((i + 1))
    done
    i=1
    while [ "$i" -le "$LARGE_COUNT" ]; do
        dd if=/dev/urandom of="$FILES_DIR/f_large_$i.bin" bs=1024 count="$LARGE_SIZE_KB" status=none
        i=$((i + 1))
    done
    compute_manifest > "$MANIFEST"
    bench::log "generated: $SMALL_COUNT x ${SMALL_SIZE_KB}KiB + $LARGE_COUNT x ${LARGE_SIZE_KB}KiB"
fi
du -sb "$FILES_DIR" | awk '{printf "total bytes: %s\n", $1}'
