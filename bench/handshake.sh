#!/usr/bin/env bash
# Handshake benchmark: full connect+auth+exec("true") cycle (TESTPLAN B4, metric M3).
# Usage: handshake.sh --stand S1 --transport ssh3 [--runs 30] [--out results/x.csv]
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

TRANSPORT="ssh3" RUNS="$HANDSHAKE_RUNS" OUT="" STAND=""

while [ $# -gt 0 ]; do
    case "$1" in
    --transport) TRANSPORT="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --stand) STAND="$2"; shift 2 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done
[ -n "$STAND" ] || bench::die "--stand is required"

bench::stand "$STAND"
if [ "$TRANSPORT" = "ssh2" ]; then CLIENT_CMD="$(bench::ssh2_cmd)"; else CLIENT_CMD="$(bench::ssh3_cmd)"; fi

bench::csv_init "$OUT" "transport,run,rc,ms"

# One warm-up run, discarded (page cache, QUIC retry, SSH key exchange caches).
bench::exec_remote "$CLIENT_CMD" "true" >/dev/null 2>&1 || true

FAILED=0
for ((i = 1; i <= RUNS; i++)); do
    T0=$(date +%s%N)
    if bench::exec_remote "$CLIENT_CMD" "true" >/dev/null 2>&1; then RC=0; else RC=1; FAILED=$((FAILED + 1)); fi
    T1=$(date +%s%N)
    MS="$(awk -v ns=$((T1 - T0)) 'BEGIN{printf "%.1f", ns/1e6}')"
    echo "$TRANSPORT,$i,$RC,$MS" | tee -a "${OUT:-/dev/null}"
    sleep 0.2
done

if [ "$FAILED" -eq "$RUNS" ]; then
    bench::die "all $RUNS handshake runs failed for $TRANSPORT"
fi
bench::log "handshake $TRANSPORT: $((RUNS - FAILED))/$RUNS ok"
if [ -n "$OUT" ] && [ -f "$OUT" ]; then
    bench::log "timing summary (ok runs only):"
    awk -F, '$3 == 0 {print $4}' "$OUT" | bench::stats_ms ms >&2 || true
fi
[ "$FAILED" -eq 0 ] || exit 1
