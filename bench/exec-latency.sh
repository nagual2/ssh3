#!/usr/bin/env bash
# B10: per-exec latency, one-shot vs ControlMaster (MCP transport profile).
#
#   exec-latency.sh [--cold-iters 100] [--cm-iters 100] [--out results/x.csv]
#                   [--port 4443] [--privkey PATH] [--user NAME] [--skip-cold]
#                   [--keep-server] [--bin DIR] [--no-build]
#
# Builds the client and the server from the working tree (bench measures the
# tree, not the deployed release), starts a private server instance on
# 127.0.0.1:<port> and stops it on exit.
#
# Modes (CSV rows share "mode,iter,rc,ms"):
#   cold     : N separate ssh3 connections (QUIC handshake + auth each)
#   cm-spawn : the first -control-master invocation, timed separately: it
#              spawns the detached master and polls for its socket
#              (waitForMaster granularity shows up here)
#   cm       : warm slaves through the master (the MCP steady state)
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

COLD_ITERS=100 CM_ITERS=100 OUT="" PORT=4443 PRIVKEY="${PRIVKEY:-$HOME/.ssh/ssh3test_ed25519}"
BENCH_USER="${BENCH_USER:-$(id -un)}" KEEP_SERVER=0 BIN="" NO_BUILD=0 SKIP_COLD=0
REPO_ROOT="$(cd "$BENCH_DIR/.." && pwd)"
WORK="${SSH3_LAT_WORKDIR:-/tmp/ssh3-exec-latency}"

while [ $# -gt 0 ]; do
    case "$1" in
    --cold-iters) COLD_ITERS="$2"; shift 2 ;;
    --cm-iters) CM_ITERS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --privkey) PRIVKEY="$2"; shift 2 ;;
    --user) BENCH_USER="$2"; shift 2 ;;
    --keep-server) KEEP_SERVER=1 ;;
    --bin) BIN="$2"; NO_BUILD=1; shift ;;
    --no-build) NO_BUILD=1 ;;
    --skip-cold) SKIP_COLD=1 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done

URL_PATH="/ssh3-term"
TARGET="$BENCH_USER@127.0.0.1:$PORT$URL_PATH"
mkdir -p "$WORK"

# --- build the tree under test into $WORK -----------------------------------
if [ "$NO_BUILD" = "0" ]; then
    bench::log "building client and server from $REPO_ROOT"
    (cd "$REPO_ROOT" && go build -o "$WORK/ssh3" ./cmd/ssh3 && go build -o "$WORK/ssh3-server" ./cmd/ssh3-server)
fi
[ -x "$WORK/ssh3" ] || bench::die "client binary $WORK/ssh3 not found (build failed?)"
[ -x "$WORK/ssh3-server" ] || bench::die "server binary $WORK/ssh3-server not found (build failed?)"

# --- private server instance (release server on :443 has other code) --------
if [ ! -f "$WORK/cert.pem" ] || [ ! -f "$WORK/priv.key" ]; then
    openssl req -x509 -sha256 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$WORK/priv.key" -days 3660 -out "$WORK/cert.pem" \
        -subj "/CN=127.0.0.1" -addext "subjectAltName = IP:127.0.0.1" 2>/dev/null
fi
KEY_ARGS=""
[ -f "$PRIVKEY" ] && KEY_ARGS="-privkey $PRIVKEY"
CLIENT_BASE="$WORK/ssh3 -insecure $KEY_ARGS"

SERVER_PID=""
start_server() {
    SSH3_LOG_FILE="$WORK/server.log" "$WORK/ssh3-server" \
        -bind "127.0.0.1:$PORT" -cert "$WORK/cert.pem" -key "$WORK/priv.key" \
        -url-path "$URL_PATH" &
    SERVER_PID=$!
}
stop_server() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap stop_server EXIT

bench::csv_init "$OUT" "mode,iter,rc,ms"

start_server
# A stale server from a previous run holding the port makes THIS process die
# on bind; catch it here so the probe below cannot measure the wrong binary.
sleep 0.5
kill -0 "$SERVER_PID" 2>/dev/null || bench::die "server died at startup (port $PORT busy? see $WORK/server.log)"

# One warm-up exec, discarded (also the readiness probe: QUIC is UDP, there
# is no TCP connect to wait for).
READY=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if $CLIENT_BASE "$TARGET" true </dev/null >/dev/null 2>&1; then READY=1; break; fi
    sleep 0.5
done
[ "$READY" = "1" ] || bench::die "server on 127.0.0.1:$PORT never became ready"

# --- cold one-shot -----------------------------------------------------------
FAILED=0
if [ "$SKIP_COLD" = "0" ]; then
    bench::log "cold one-shot: $COLD_ITERS execs"
    for ((i = 1; i <= COLD_ITERS; i++)); do
        T0=$(date +%s%N)
        if $CLIENT_BASE "$TARGET" true </dev/null >/dev/null 2>&1; then RC=0; else RC=1; FAILED=$((FAILED + 1)); fi
        T1=$(date +%s%N)
        MS="$(awk -v ns=$((T1 - T0)) 'BEGIN{printf "%.1f", ns/1e6}')"
        echo "cold,$i,$RC,$MS" | tee -a "${OUT:-/dev/null}"
        sleep 0.05
    done
fi

# --- ControlMaster: spawn once, then warm slaves -----------------------------
CTL="$WORK/cm-$$.sock"
CM_ARGS="-control-master yes -control-persist yes -control-path $CTL"
bench::log "cm: master spawn + $CM_ITERS warm execs"
T0=$(date +%s%N)
if $CLIENT_BASE $CM_ARGS "$TARGET" true </dev/null >/dev/null 2>&1; then RC=0; else RC=1; FAILED=$((FAILED + 1)); fi
T1=$(date +%s%N)
MS="$(awk -v ns=$((T1 - T0)) 'BEGIN{printf "%.1f", ns/1e6}')"
echo "cm-spawn,1,$RC,$MS" | tee -a "${OUT:-/dev/null}"
for ((i = 1; i <= CM_ITERS; i++)); do
    T0=$(date +%s%N)
    if $CLIENT_BASE $CM_ARGS "$TARGET" true </dev/null >/dev/null 2>&1; then RC=0; else RC=1; FAILED=$((FAILED + 1)); fi
    T1=$(date +%s%N)
    MS="$(awk -v ns=$((T1 - T0)) 'BEGIN{printf "%.1f", ns/1e6}')"
    echo "cm,$i,$RC,$MS" | tee -a "${OUT:-/dev/null}"
    sleep 0.05
done
$CLIENT_BASE -O exit -control-path "$CTL" dummy </dev/null >/dev/null 2>&1 || true
rm -f "$CTL" 2>/dev/null || true

if [ "$FAILED" -gt 0 ]; then
    bench::die "$FAILED executions failed"
fi

if [ -n "$OUT" ] && [ -f "$OUT" ]; then
    for m in cold cm-spawn cm; do
        if grep -q "^$m," "$OUT"; then
            bench::log "$m summary:"
            awk -F, -v m="$m" '$1 == m && $3 == 0 {print $4}' "$OUT" | bench::stats_ms ms >&2
        fi
    done
fi
