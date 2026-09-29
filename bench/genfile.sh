#!/usr/bin/env bash
# Generate the benchmark payload file in tmpfs (idempotent).
# Usage: genfile.sh [--check|--clean]   (SIZE_MB env overrides size, default 512)
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

FILE="$LOCAL_FILE"
SHA_FILE="$FILE.sha256"

case "${1:-}" in
--clean)
    rm -f "$FILE" "$SHA_FILE"
    echo "cleaned: $FILE"
    exit 0
    ;;
--check)
    if [ -f "$FILE" ] && [ -f "$SHA_FILE" ] && sha256sum -c "$SHA_FILE" >/dev/null 2>&1; then
        echo "payload OK"
        exit 0
    fi
    echo "payload MISSING or CORRUPT"
    exit 1
    ;;
"") ;;
*) bench::die "unknown argument: $1 (use --check or --clean)" ;;
esac

mkdir -p "$(dirname "$FILE")"
EXPECTED_BYTES=$((SIZE_MB * 1024 * 1024))
ACTUAL_BYTES=0
[ -f "$FILE" ] && ACTUAL_BYTES=$(stat -c%s "$FILE")
if [ -f "$FILE" ] && [ -f "$SHA_FILE" ] && [ "$ACTUAL_BYTES" -eq "$EXPECTED_BYTES" ] &&
    sha256sum -c "$SHA_FILE" >/dev/null 2>&1; then
    bench::log "payload OK: $FILE"
else
    dd if=/dev/urandom of="$FILE" bs=1M count="$SIZE_MB" status=none
    sha256sum "$FILE" > "$SHA_FILE"
    bench::log "payload generated: $FILE ($SIZE_MB MiB)"
fi
bench::local_sha "$FILE"
