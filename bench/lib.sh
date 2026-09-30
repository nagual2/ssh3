#!/usr/bin/env bash
# Shared helpers for the SSH2 vs SSH3 benchmark suite (TESTPLAN.md R3).
# Sourced by every bench script; reads bench/config.env when present.

# BENCH_DIR is the directory containing this script.
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bench::die() { echo "bench: ERROR: $*" >&2; exit 1; }
bench::log() { echo "[bench] $*" >&2; }

# Load local config (gitignored) if present; environment keeps priority over
# config.env, defaults below have the lowest priority.
if [ -f "$BENCH_DIR/config.env" ]; then
    declare -A _BENCH_ENV_KEEP=()
    while read -r _v; do
        [ -n "$_v" ] && _BENCH_ENV_KEEP["$_v"]="${!_v}"
    done < <(compgen -e | grep -E '^(S[0-9]+_|CPU_PIDCMD_|SIZE_MB$|RUNS$|HANDSHAKE_RUNS$|RTT_ITERS$|PAUSE_S$|REMOTE_DIR$|LOCAL_FILE$|SSH2_CIPHER$|SSH3_BIN$|SSH3_ARGS$)' || true)
    # shellcheck disable=SC1091
    source "$BENCH_DIR/config.env"
    for _v in "${!_BENCH_ENV_KEEP[@]}"; do
        printf -v "$_v" '%s' "${_BENCH_ENV_KEEP[$_v]}"
    done
    unset _BENCH_ENV_KEEP _v
fi

# Defaults (override via config.env or environment).
SIZE_MB="${SIZE_MB:-512}"
RUNS="${RUNS:-10}"
HANDSHAKE_RUNS="${HANDSHAKE_RUNS:-30}"
RTT_ITERS="${RTT_ITERS:-100}"
PAUSE_S="${PAUSE_S:-2}"
REMOTE_DIR="${REMOTE_DIR:-/dev/shm/ssh3-bench}"
LOCAL_FILE="${LOCAL_FILE:-/dev/shm/ssh3-bench.bin}"
SSH2_CIPHER="${SSH2_CIPHER:-aes128-gcm@openssh.com}"
SSH3_BIN="${SSH3_BIN:-ssh3}"
SSH3_ARGS="${SSH3_ARGS:--insecure}"

# Resolve per-stand variables; $1 = stand id (S1, S2, ...).
# Requires in config/env: <STAND>_SSH3_TARGET="user@host:port/url-path",
# <STAND>_SSH2_DEST="user@host", <STAND>_SSH2_PORT.
bench::stand() {
    local s="$1"
    SSH3_TARGET_VAR="${s}_SSH3_TARGET"
    SSH2_DEST_VAR="${s}_SSH2_DEST"
    SSH2_PORT_VAR="${s}_SSH2_PORT"
    STAND_SSH3_TARGET="${!SSH3_TARGET_VAR:-}"
    STAND_SSH2_DEST="${!SSH2_DEST_VAR:-}"
    STAND_SSH2_PORT="${!SSH2_PORT_VAR:-22}"
    [ -n "$STAND_SSH3_TARGET" ] || bench::die "$SSH3_TARGET_VAR is not set (config.env)"
    [ -n "$STAND_SSH2_DEST" ] || bench::die "$SSH2_DEST_VAR is not set (config.env)"
}

# Full client command line (without remote command) for each transport.
bench::ssh2_cmd() {
    echo "ssh -c $SSH2_CIPHER -o BatchMode=yes -o Compression=no -p $STAND_SSH2_PORT $STAND_SSH2_DEST"
}

bench::ssh3_cmd() {
    echo "$SSH3_BIN $SSH3_ARGS $STAND_SSH3_TARGET"
}

# Run a remote command: exec_remote "<client cmd>" "<remote cmd>".
# Stdin is closed on purpose: command execution never streams input. With an
# inherited (possibly never-EOF) pipe the ssh3 client keeps its stdin pump
# alive and, after a fast remote exit, deadlocks in the post-exit drain
# waiting for a server FIN that only follows a client FIN (see
# docs/BUG-STDIN-DRAIN-DEADLOCK.md). Payload streaming goes through
# bench::exec_remote_stdin.
bench::exec_remote() {
    eval "$1 $(printf '%q' "$2")" </dev/null
}

# Run a remote command with the caller's stdin passed through: for piped
# payload/tar streams (cat payload | exec_remote_stdin "cat > file").
bench::exec_remote_stdin() {
    eval "$1 $(printf '%q' "$2")"
}

# Pipe a local script through the transport to remote `bash -s`.
# Extra args are passed to the remote bash invocation, each quoted separately
# (args may contain spaces, e.g. --pid-cmd 'systemctl show -p MainPID ...').
bench::exec_remote_script() {
    local client_cmd="$1" script="$2" rcmd="bash -s --" a
    shift 2
    for a in "$@"; do
        rcmd+=" $(printf '%q' "$a")"
    done
    eval "$client_cmd $(printf '%q' "$rcmd")" < "$script"
}

# Remote sha256 of a file (hex digest only); "" when the file is missing or
# the exec fails. Never fails the caller under set -e -o pipefail.
# TRAP client-exec-trailing-cr: the ssh3 client appends a stray "\r" to the
# exec stdout — strip it or sha comparison sees "\r" instead of "".
bench::remote_sha() {
    {
        bench::exec_remote "$1" "sha256sum '$2' 2>/dev/null" | awk '{print $1}' | tr -d '\r' | head -1
    } || true
}

# Local sha256 (hex digest only).
bench::local_sha() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# Stats over a duration list on stdin: min/median/p95/max in ms.
# $1 = input unit: "ns" (default) or "ms".
bench::stats_ms() {
    local div=1000000
    [ "${1:-ns}" = "ms" ] && div=1
    sort -g | awk -v d="$div" '{a[NR]=$1} END {
        if (NR == 0) exit 1
        med = (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2
        i = int(NR * 0.95 + 0.999); if (i > NR) i = NR
        printf "min=%.1fms median=%.1fms p95=%.1fms max=%.1fms n=%d\n", a[1]/d, med/d, a[i]/d, a[NR]/d, NR
    }'
}

# Ensure the CSV output file exists and has the given header.
bench::csv_init() {
    local out="$1" header="$2"
    [ -z "$out" ] && return 0
    mkdir -p "$(dirname "$out")"
    [ -f "$out" ] || echo "$header" > "$out"
}

bench::require_file() {
    [ -f "$1" ] || bench::die "file '$1' not found (run bench/genfile.sh first)"
}
