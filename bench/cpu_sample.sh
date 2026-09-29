#!/usr/bin/env bash
# CPU/RSS sampler for a server process tree (TESTPLAN B6, metric M5).
# Samples utime+stime across the process tree (sshd session child and ssh3-server
# both spawn children that belong to the server-side cost).
#
# Usage:
#   cpu_sample.sh --pid 1234 --secs 30 [--interval 1] [--out cpu.csv]
#   cpu_sample.sh --pid-cmd 'systemctl show -p MainPID --value ssh3-server' --secs 30
set -euo pipefail
# Self-contained on purpose: this script is piped to the remote host via
# `bash -s`, where BASH_SOURCE/lib.sh are not available.
bench::die() { echo "bench: ERROR: $*" >&2; exit 1; }
bench::csv_init() {
    local out="$1" header="$2"
    [ -z "$out" ] && return 0
    mkdir -p "$(dirname "$out")"
    [ -f "$out" ] || echo "$header" > "$out"
}

PID="" PID_CMD="" SECS=30 INTERVAL=1 OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
    --pid) PID="$2"; shift 2 ;;
    --pid-cmd) PID_CMD="$2"; shift 2 ;;
    --secs) SECS="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done
[ -n "$PID" ] || [ -n "$PID_CMD" ] || bench::die "--pid or --pid-cmd is required"

CLK_TCK="$(getconf CLK_TCK)"
PAGESIZE="$(getconf PAGESIZE)"

bench::csv_init "$OUT" "ts,root_pid,nprocs,cpu_pct,rss_kb"

# One pass over /proc: "pid ppid utime stime rss_pages"
read_proc() {
    awk '{
        f = FILENAME
        sub(/^\/proc\//, "", f); sub(/\/stat$/, "", f)
        i = index($0, ")")
        n = split(substr($0, i + 2), a, " ")
        if (n >= 22) print f, a[2], a[12], a[13], a[22]
    }' /proc/[0-9]*/stat 2>/dev/null || true
}

resolve_pid() {
    if [ -n "$PID" ]; then
        [ -d "/proc/$PID" ] && { echo "$PID"; return 0; }
        return 1
    fi
    local p
    p="$(eval "$PID_CMD" 2>/dev/null | head -1 | tr -dc '0-9')"
    [ -n "$p" ] && [ -d "/proc/$p" ] && { echo "$p"; return 0; }
    return 1
}

# Collect the tree of $1 into the arrays PID_PPID etc.; echoes process count.
collect_tree() {
    local root="$1"
    declare -gA KIDS=()
    local line pid ppid ut st rss
    while read -r pid ppid ut st rss; do
        KIDS[$ppid]="${KIDS[$ppid]:-} $pid"
        PPID_OF[$pid]=$ppid
        UT[$pid]=$ut; ST[$pid]=$st; RSS[$pid]=$rss
    done < <(read_proc)
    TREE=("$root")
    local qi=0
    while [ "$qi" -lt "${#TREE[@]}" ]; do
        local cur="${TREE[$qi]}"
        qi=$((qi + 1))
        for p in ${KIDS[$cur]:-}; do
            TREE+=("$p")
        done
    done
}

declare -A PPID_OF=() UT=() ST=() RSS=()
PREV_JIFFIES=0
ROOT_PID=""
END=$((SECONDS + SECS))

while [ "$SECONDS" -lt "$END" ]; do
    if ! ROOT_PID="$(resolve_pid)"; then
        ROOT_PID=""
        sleep "$INTERVAL"
        continue
    fi
    PPID_OF=(); UT=(); ST=(); RSS=()
    collect_tree "$ROOT_PID" # fills TREE/UT/ST/RSS (must not run in a subshell)
    NPROC="${#TREE[@]}"
    SUM=0; RSS_KB=0
    for p in "${TREE[@]}"; do
        SUM=$((SUM + ${UT[$p]:-0} + ${ST[$p]:-0}))
        RSS_KB=$((RSS_KB + ${RSS[$p]:-0} * PAGESIZE / 1024))
    done
    if [ "$PREV_JIFFIES" -gt 0 ]; then
        CPU="$(awk -v d=$((SUM - PREV_JIFFIES)) -v hz="$CLK_TCK" -v iv="$INTERVAL" 'BEGIN{printf "%.1f", d*100/hz/iv}')"
    else
        CPU="0.0" # first tick: baseline sample, no delta yet
    fi
    echo "$(date +%s),${ROOT_PID},${NPROC},${CPU},${RSS_KB}" | tee -a "${OUT:-/dev/null}"
    PREV_JIFFIES=$SUM
    sleep "$INTERVAL"
done
