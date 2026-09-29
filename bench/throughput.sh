#!/usr/bin/env bash
# Bulk-throughput benchmark: SSH2 vs SSH3 over identical mechanisms (TESTPLAN B1-B3).
#
# Usage:
#   throughput.sh --stand S1 --transport ssh3 --dir push --runs 10 [--k 1]
#                 [--mech pipe|file] [--size-mb 512] [--out results/x.csv]
#                 [--warmup 1] [--setup-remote]
#
# mech=pipe : stdin pipe "cat > out" — the fair baseline, identical for both transports.
# mech=file : real file copy; ssh3 uses "-f", ssh2 uses scp. Push only (pull not
#             supported by ssh3 -f), reference scenario, not the parity baseline.
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

TRANSPORT="ssh3" DIR="push" K=1 RUNS="$RUNS" MECH="pipe" OUT="" WARMUP=1 SETUP_REMOTE=0 STAND=""

while [ $# -gt 0 ]; do
    case "$1" in
    --transport) TRANSPORT="$2"; shift 2 ;;
    --dir) DIR="$2"; shift 2 ;;
    --k) K="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --mech) MECH="$2"; shift 2 ;;
    --size-mb) SIZE_MB="$2"; shift 2 ;; # affects payload (re)generation by genfile
    --out) OUT="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --stand) STAND="$2"; shift 2 ;;
    --setup-remote) SETUP_REMOTE=1; shift ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done

case "$TRANSPORT:$DIR:$MECH" in
ssh2:push:pipe | ssh2:pull:pipe | ssh3:push:pipe | ssh3:pull:pipe | ssh2:push:file | ssh3:push:file) ;;
ssh3:pull:file) bench::die "mech=file pull is not supported by ssh3 -f; use --mech pipe" ;;
*) bench::die "bad combination: transport=$TRANSPORT dir=$DIR mech=$MECH" ;;
esac
[ -n "$STAND" ] || bench::die "--stand is required"

bench::stand "$STAND"
if [ "$TRANSPORT" = "ssh2" ]; then CLIENT_CMD="$(bench::ssh2_cmd)"; else CLIENT_CMD="$(bench::ssh3_cmd)"; fi

bench::require_file "$LOCAL_FILE"
ACTUAL_BYTES=$(stat -c%s "$LOCAL_FILE")
EXPECTED_BYTES=$((SIZE_MB * 1024 * 1024))
[ "$ACTUAL_BYTES" -eq "$EXPECTED_BYTES" ] ||
    bench::die "payload is $ACTUAL_BYTES bytes but --size-mb $SIZE_MB expected $EXPECTED_BYTES (rerun genfile.sh)"
REF_SHA="$(bench::local_sha "$LOCAL_FILE")"
[ -n "$REF_SHA" ] || bench::die "cannot hash $LOCAL_FILE"
BYTES=$((SIZE_MB * 1024 * 1024))
TOTAL_MB=$((SIZE_MB * K))
# Pull outputs go to tmpfs next to the payload: writing to cwd (often /mnt/c,
# 9p filesystem) would bottleneck the measured network throughput.
LOCAL_OUT="$(dirname "$LOCAL_FILE")/ssh3-bench.out"

bench::csv_init "$OUT" "transport,mech,dir,k,run,valid,seconds,mb,mbps"

bench::exec_remote "$CLIENT_CMD" "mkdir -p '$REMOTE_DIR'" >/dev/null
if [ "$MECH" = "file" ]; then
    # ssh3 -f does not create remote directories; the dir survives between runs
    bench::exec_remote "$CLIENT_CMD" "mkdir -p ssh3-bench-file" >/dev/null
fi

if [ "$DIR" = "pull" ]; then
    RSHA="$(bench::remote_sha "$CLIENT_CMD" "$REMOTE_DIR/payload.bin")"
    if [ "$RSHA" != "$REF_SHA" ]; then
        [ "$SETUP_REMOTE" = "1" ] || bench::die "remote payload missing/mismatched; rerun with --setup-remote"
        bench::log "uploading payload to remote (one-time)..."
        cat "$LOCAL_FILE" | bench::exec_remote "$CLIENT_CMD" "cat > '$REMOTE_DIR/payload.bin'"
        RSHA="$(bench::remote_sha "$CLIENT_CMD" "$REMOTE_DIR/payload.bin")"
        [ "$RSHA" = "$REF_SHA" ] || bench::die "remote payload sha mismatch after upload"
    fi
fi

run_once() { # $1 = run index; echoes elapsed ns on stdout, returns 0 on success
    local i="$1" j rc=0 p
    local t0 t1
    t0=$(date +%s%N)
    case "$TRANSPORT:$MECH:$DIR" in
    *:pipe:push)
        for ((j = 1; j <= K; j++)); do
            cat "$LOCAL_FILE" | bench::exec_remote "$CLIENT_CMD" "cat > '$REMOTE_DIR/out.$i.$j'" &
        done
        wait || rc=1
        ;;
    *:pipe:pull)
        for ((j = 1; j <= K; j++)); do
            bench::exec_remote "$CLIENT_CMD" "cat '$REMOTE_DIR/payload.bin'" > "$LOCAL_OUT.$i.$j" &
        done
        wait || rc=1
        ;;
    ssh3:file:push)
        # TRAP: ssh3 -f accepts only HOME-relative remote paths (fork bug)
        eval "$SSH3_BIN $SSH3_ARGS -f '$LOCAL_FILE' $(printf '%q' "$STAND_SSH3_TARGET"):'ssh3-bench-file/out.$i.1'" || rc=1
        ;;
    ssh2:file:push)
        eval "scp -q -P $STAND_SSH2_PORT -c $SSH2_CIPHER -o BatchMode=yes '$LOCAL_FILE' $(printf '%q' "$STAND_SSH2_DEST"):'ssh3-bench-file/out.$i.1'" || rc=1
        ;;
    esac
    t1=$(date +%s%N)
    echo $((t1 - t0))
    return $rc
}

verify_outputs() { # $1 = run index; returns 0 when all outputs match the reference sha
    local i="$1" j sha rp
    if [ "$DIR" = "push" ]; then
        for ((j = 1; j <= K; j++)); do
            if [ "$MECH" = "file" ]; then rp="ssh3-bench-file/out.$i.1"; else rp="$REMOTE_DIR/out.$i.$j"; fi
            sha="$(bench::remote_sha "$CLIENT_CMD" "$rp")"
            [ "$sha" = "$REF_SHA" ] || return 1
        done
    else
        for ((j = 1; j <= K; j++)); do
            local f="$LOCAL_OUT.$i.$j" sz
            sz=$(stat -c%s "$f" 2>/dev/null || echo 0)
            # TRAP client-exec-trailing-cr: the client appends a stray CR to the
            # exec stdout, so a binary pull is 1 byte longer than the payload.
            # Fork bug; until fixed, strip the trailing CR before comparing.
            if [ "$sz" -eq "$((BYTES + 1))" ]; then
                [ "$(tail -c 1 "$f" | od -An -tu1 | tr -d ' \n')" = "13" ] &&
                    truncate -s "$BYTES" "$f"
            fi
            [ "$(bench::local_sha "$f")" = "$REF_SHA" ] || {
                bench::log "pull mismatch: got $sz bytes, expected $BYTES (truncation under host load?)"
                return 1
            }
        done
    fi
    return 0
}

cleanup_run() {
    local i="$1" j
    if [ "$MECH" = "file" ]; then
        bench::exec_remote "$CLIENT_CMD" "rm -f ssh3-bench-file/out.$i.1" >/dev/null 2>&1 || true
        return
    fi
    if [ "$DIR" = "push" ]; then
        bench::exec_remote "$CLIENT_CMD" "rm -f $(for ((j = 1; j <= K; j++)); do printf "'%s/out.%s.%s' " "$REMOTE_DIR" "$i" "$j"; done)" >/dev/null 2>&1 || true
    else
        rm -f "$LOCAL_OUT.$i".* 2>/dev/null || true
    fi
}

VALID=0 ATTEMPT=0 MAX_ATTEMPTS=$((RUNS * 2))
while [ "$VALID" -lt "$RUNS" ] && [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    [ "$ATTEMPT" -le "$WARMUP" ] && ROLE="warmup" || ROLE="measured"
    i="$ATTEMPT"
    NS="$(run_once "$i")" || {
        echo "$TRANSPORT,$MECH,$DIR,$K,$i,0,,$TOTAL_MB," >> "${OUT:-/dev/null}"
        cleanup_run "$i"
        bench::log "run $i failed (transport error)"
        continue
    }
    if verify_outputs "$i"; then
        SEC="$(awk -v ns="$NS" 'BEGIN{printf "%.3f", ns/1e9}')"
        MBPS="$(awk -v b=$((BYTES * K)) -v ns="$NS" 'BEGIN{printf "%.2f", b/1e6/(ns/1e9)}')"
        if [ "$ROLE" = "measured" ]; then
            VALID=$((VALID + 1))
            echo "$TRANSPORT,$MECH,$DIR,$K,$i,1,$SEC,$TOTAL_MB,$MBPS" | tee -a "${OUT:-/dev/null}"
        else
            bench::log "warmup done ($TRANSPORT $DIR k=$K)"
        fi
    else
        echo "$TRANSPORT,$MECH,$DIR,$K,$i,0,$(awk -v ns="$NS" 'BEGIN{printf "%.3f", ns/1e9}'),$TOTAL_MB," >> "${OUT:-/dev/null}"
        bench::log "run $i sha mismatch — discarded"
    fi
    cleanup_run "$i"
    sleep "$PAUSE_S"
done

cleanup_run "$ATTEMPT" 2>/dev/null || true
bench::log "done: $VALID/$RUNS valid runs ($TRANSPORT $MECH $DIR k=$K)"
if [ "$VALID" -lt "$RUNS" ]; then
    bench::log "insufficient valid runs (see discarded rows above)"
    exit 1
fi
