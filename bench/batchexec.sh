#!/usr/bin/env bash
# B9: many command executions in one session (TESTPLAN §5).
#
#   batchexec.sh --stand S2 --mode ssh2cold [--iters 100] [--out x.csv]
#   batchexec.sh --stand S2 --mode ssh2cm
#   batchexec.sh --stand S2 --mode ssh3cli
#
# Modes:
#   ssh2cold : N separate ssh2 connections (no ControlMaster)
#   ssh2cm   : OpenSSH ControlMaster — 1 connection, N execs over the UDS
#   ssh3cli  : current ssh3 CLI — each exec is its own QUIC connection
#              (a ControlMaster equivalent is stage 3.5, pending)
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

MODE="ssh3cli" ITERS=100 OUT="" STAND=""

while [ $# -gt 0 ]; do
    case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --iters) ITERS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --stand) STAND="$2"; shift 2 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done
[ -n "$STAND" ] || bench::die "--stand is required"
bench::stand "$STAND"

SSH2_BASE="ssh -c $SSH2_CIPHER -o BatchMode=yes -o Compression=no -p $STAND_SSH2_PORT"
SSH3_BASE="$SSH3_BIN $SSH3_ARGS"

case "$MODE" in
ssh2cm)
    CTL="/tmp/ssh3-bench-cm-$$"
    MASTER_CMD="$SSH2_BASE -o ControlMaster=yes -o ControlPath=$CTL -o ControlPersist=no -fN $STAND_SSH2_DEST"
    SLAVE_CMD="$SSH2_BASE -o ControlPath=$CTL $STAND_SSH2_DEST"
    ;;
ssh2cold) SLAVE_CMD="$SSH2_BASE $STAND_SSH2_DEST" ;;
ssh3cli) SLAVE_CMD="$SSH3_BASE $STAND_SSH3_TARGET" ;;
*) bench::die "unknown mode: $MODE" ;;
esac

bench::csv_init "$OUT" "mode,iter,rc,ms"

if [ "$MODE" = "ssh2cm" ]; then
    bench::log "starting ControlMaster..."
    eval "$MASTER_CMD"
    READY=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if eval "$SSH2_BASE -o ControlPath=$CTL -O check $STAND_SSH2_DEST" >/dev/null 2>&1; then READY=1; break; fi
        sleep 0.5
    done
    [ "$READY" = "1" ] || bench::die "ControlMaster socket never became ready"
fi

FAILED=0
for ((i = 1; i <= ITERS; i++)); do
    T0=$(date +%s%N)
    if [ "$MODE" = "ssh2cm" ]; then
        eval "$SLAVE_CMD true" >/dev/null 2>&1 && RC=0 || RC=1
    else
        bench::exec_remote "$SLAVE_CMD" "true" >/dev/null 2>&1 && RC=0 || RC=1
    fi
    T1=$(date +%s%N)
    [ "$RC" = "0" ] || FAILED=$((FAILED + 1))
    MS="$(awk -v ns=$((T1 - T0)) 'BEGIN{printf "%.1f", ns/1e6}')"
    echo "$MODE,$i,$RC,$MS" | tee -a "${OUT:-/dev/null}"
    sleep 0.05
done

if [ "$MODE" = "ssh2cm" ]; then
    eval "$SSH2_BASE -o ControlPath=$CTL -O exit $STAND_SSH2_DEST" >/dev/null 2>&1 || true
    rm -f "$CTL" 2>/dev/null || true
fi

if [ "$FAILED" -gt 0 ]; then
    bench::die "$FAILED/$ITERS executions failed"
fi
bench::log "batchexec $MODE: $ITERS ok; per-exec summary:"
awk -F, '$3 == 0 {print $4}' "${OUT:-/dev/null}" 2>/dev/null | bench::stats_ms ms >&2 || true
