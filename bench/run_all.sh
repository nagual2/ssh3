#!/usr/bin/env bash
# Orchestrator for the SSH2 vs SSH3 benchmark matrix (TESTPLAN R3, scenarios B1-B7).
#
# Usage:
#   run_all.sh --stand S1 [--profile quick|full] [--outdir DIR]
#              [--netem-loss 2 --netem-delay 50 --netem-iface eth0]
#
# netem applies on the host reachable via SSH2 (the benchmark server) and needs
# passwordless sudo there; it is skipped gracefully when sudo is unavailable.
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

STAND="" PROFILE="full" OUTDIR="" NETEM_LOSS="" NETEM_DELAY="" NETEM_IFACE="" TRANSPORTS="ssh2 ssh3"

while [ $# -gt 0 ]; do
    case "$1" in
    -s | --stand) STAND="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    --transports) TRANSPORTS="$2"; shift 2 ;;
    --netem-loss) NETEM_LOSS="$2"; shift 2 ;;
    --netem-delay) NETEM_DELAY="$2"; shift 2 ;;
    --netem-iface) NETEM_IFACE="$2"; shift 2 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done
[ -n "$STAND" ] || bench::die "--stand is required (S1, S2, ...)"
bench::stand "$STAND"

has_tr() { case " $TRANSPORTS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

if [ "$PROFILE" = "quick" ]; then
    RUNS=5; SIZE_MB=128; HANDSHAKE_RUNS=10; RTT_ITERS=20; KS="4"
else
    KS="2 4 8"
fi

OUTDIR="${OUTDIR:-$BENCH_DIR/results/$(date -u +%Y%m%dT%H%M%SZ)-$STAND-$PROFILE}"
mkdir -p "$OUTDIR"

SSH2_CMD="$(bench::ssh2_cmd)"
SSH3_CMD="$(bench::ssh3_cmd)"
CPU_PIDCMD_SSH3="${CPU_PIDCMD_SSH3:-systemctl show -p MainPID --value ssh3-server}"
CPU_PIDCMD_SSH2="${CPU_PIDCMD_SSH2:-pgrep -n -x sshd}"
NETEM_APPLIED=0

cleanup() {
    set +e
    if [ "$NETEM_APPLIED" = "1" ]; then
        bench::log "removing netem qdisc from $NETEM_IFACE"
        bench::exec_remote "$SSH2_CMD" "tc qdisc del dev $NETEM_IFACE root" >/dev/null 2>&1
        bench::exec_remote "$SSH2_CMD" "tc qdisc show dev $NETEM_IFACE" 2>/dev/null
    fi
}
trap cleanup EXIT

tp() { # throughput wrapper: tp <transport> <dir> <k> <runs> <extra args...>
    local tr="$1" dir="$2" k="$3" runs="$4"
    shift 4
    bash "$BENCH_DIR/throughput.sh" --stand "$STAND" --transport "$tr" --dir "$dir" \
        --k "$k" --runs "$runs" --size-mb "$SIZE_MB" --warmup 0 --out "$OUTDIR/throughput.csv" "$@" ||
        bench::log "WARN: throughput scenario failed (transport=$tr dir=$dir k=$k runs=$runs) — continuing"
}

# --- 0. Reachability -------------------------------------------------------
bench::log "stand $STAND: checking targets ($TRANSPORTS)"
if has_tr ssh2; then
    bench::exec_remote "$SSH2_CMD" "true" >/dev/null || bench::die "ssh2 target unreachable: $SSH2_CMD"
fi
if has_tr ssh3; then
    bench::exec_remote "$SSH3_CMD" "true" >/dev/null || bench::die "ssh3 target unreachable: $SSH3_CMD"
fi

# --- 1. Payload ------------------------------------------------------------
SIZE_MB="$SIZE_MB" bash "$BENCH_DIR/genfile.sh"
bench::log "pushing payload to remote (for pull scenarios)"
cat "$LOCAL_FILE" | bench::exec_remote "$SSH3_CMD" "mkdir -p '$REMOTE_DIR' && cat > '$REMOTE_DIR/payload.bin'"
if has_tr ssh2; then
    [ "$(bench::remote_sha "$SSH2_CMD" "$REMOTE_DIR/payload.bin")" = "$(bench::local_sha "$LOCAL_FILE")" ] \
        || bench::die "remote payload sha mismatch (via ssh2)"
fi

# --- 2. B1/B2: push & pull, k=1, strict ABBA -------------------------------
bench::log "B1/B2: push+pull k=1, $RUNS rounds ABBA"
for ((i = 1; i <= RUNS; i++)); do
    if has_tr ssh2; then tp ssh2 push 1 1; fi
    if has_tr ssh3; then tp ssh3 push 1 1; fi
done
if has_tr ssh3; then tp ssh3 pull 1 1; fi # first pull run doubles as sha verification
for ((i = 1; i <= RUNS; i++)); do
    if has_tr ssh2; then tp ssh2 pull 1 1; fi
    if has_tr ssh3; then tp ssh3 pull 1 1; fi
done

# --- 3. B3: parallel streams -----------------------------------------------
bench::log "B3: aggregate k in ($KS), 3 rounds per point"
for k in $KS; do
    # scale the per-stream block so k concurrent outputs + the payload fit
    # into /dev/shm (loopback runs share one tmpfs between both endpoints)
    case "$k" in
    2) SZ=256 ;;
    4) SZ=128 ;;
    *) SZ=64 ;;
    esac
    SIZE_MB="$SZ" bash "$BENCH_DIR/genfile.sh" >/dev/null # payload must match the scaled block
    for ((i = 1; i <= 3; i++)); do
        if has_tr ssh2; then tp ssh2 push "$k" 1 --size-mb "$SZ"; fi
        if has_tr ssh3; then tp ssh3 push "$k" 1 --size-mb "$SZ"; fi
    done
done
SIZE_MB="$SIZE_MB" bash "$BENCH_DIR/genfile.sh" >/dev/null # restore the canonical payload

# --- 4. B6: server CPU/RSS during one big push per transport ---------------
bench::log "B6: server cpu/rss sampling"
CPU_SECS=$((SIZE_MB / 15 + 15))
for tr in $TRANSPORTS; do
    if [ "$tr" = "ssh2" ]; then CMD="$SSH2_CMD"; PIDCMD="$CPU_PIDCMD_SSH2"; else CMD="$SSH3_CMD"; PIDCMD="$CPU_PIDCMD_SSH3"; fi
    (
        bench::exec_remote_script "$CMD" "$BENCH_DIR/cpu_sample.sh" \
            --pid-cmd "$PIDCMD" --secs "$CPU_SECS" --interval 1 | tr -d '\r'
    ) > "$OUTDIR/cpu_$tr.csv" &
    SAMPLER=$!
    sleep 2
    tp "$tr" push 1 1
    wait "$SAMPLER" || bench::log "warning: sampler for $tr exited non-zero"
done

# --- 5. B4: handshake -------------------------------------------------------
bench::log "B4: handshake x$HANDSHAKE_RUNS"
if has_tr ssh2; then
    bash "$BENCH_DIR/handshake.sh" --stand "$STAND" --transport ssh2 --runs "$HANDSHAKE_RUNS" --out "$OUTDIR/handshake.csv"
fi
if has_tr ssh3; then
    bash "$BENCH_DIR/handshake.sh" --stand "$STAND" --transport ssh3 --runs "$HANDSHAKE_RUNS" --out "$OUTDIR/handshake.csv"
fi

# --- 6. B5: PTY echo RTT ----------------------------------------------------
bench::log "B5: pty echo RTT x$RTT_ITERS"
if has_tr ssh2; then
    CLIENT_CMD="$SSH2_CMD" python3 "$BENCH_DIR/pty_rtt.py" --label ssh2 --iters "$RTT_ITERS" --out "$OUTDIR/pty_rtt.csv"
fi
if has_tr ssh3; then
    CLIENT_CMD="$SSH3_CMD" python3 "$BENCH_DIR/pty_rtt.py" --label ssh3 --iters "$RTT_ITERS" --out "$OUTDIR/pty_rtt.csv"
fi

# --- 7. B7: netem (optional, apply last, remove in trap) --------------------
if [ -n "$NETEM_LOSS" ] || [ -n "$NETEM_DELAY" ]; then
    case "$STAND_SSH2_DEST" in
    *127.0.0.1* | *localhost*) bench::die "netem is meaningless on loopback (stand $STAND)" ;;
    esac
    [ -n "$NETEM_IFACE" ] || bench::die "--netem-iface is required with --netem-loss/--netem-delay"
    LOSS="${NETEM_LOSS:-0}"; DELAY="${NETEM_DELAY:-0}ms"
    bench::log "B7: applying netem loss=$LOSS% delay=$DELAY on $NETEM_IFACE (server side)"
    if bench::exec_remote "$SSH2_CMD" "sudo -n tc qdisc add dev $NETEM_IFACE root netem loss ${LOSS}% delay ${DELAY}" >/dev/null; then
        NETEM_APPLIED=1
        sleep 1
        for ((i = 1; i <= 5; i++)); do
            tp ssh2 push 1 1
            tp ssh3 push 1 1
            tp ssh2 pull 1 1
            tp ssh3 pull 1 1
        done
    else
        bench::log "netem skipped: no passwordless sudo on the server for tc"
    fi
fi

# --- 8. Environment snapshot -------------------------------------------------
{
    echo "date_utc=$(date -u +%FT%TZ)"
    echo "stand=$STAND profile=$PROFILE"
    echo "kernel=$(uname -r)"
    echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "aes_ni=$(grep -om1 ' aes' /proc/cpuinfo | xargs || echo none)"
    echo "ssh_client_version=$(ssh -V 2>&1)"
    echo "ssh3_client_version=$("$SSH3_BIN" -version 2>&1 | grep -v '"' | tail -1)"
    IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
    [ -n "$IFACE" ] && echo "client_iface_mtu=$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null) ($IFACE)"
    echo "netem_loss=${NETEM_LOSS:-0} netem_delay=${NETEM_DELAY:-0}ms"
    echo "--- config.env (masked) ---"
    sed -E 's/(-privkey[= ])[^ ]+/\1<masked>/; s/^((.*KEY.*|.*TOKEN.*|.*PASS.*)=).*/\1<masked>/' "$BENCH_DIR/config.env" 2>/dev/null
} > "$OUTDIR/env.txt"

bench::log "done. results in: $OUTDIR"
ls -la "$OUTDIR"
