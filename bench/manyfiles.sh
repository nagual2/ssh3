#!/usr/bin/env bash
# B8: many-small-files transfer (TESTPLAN §5).
#
#   manyfiles.sh --stand S2 --transport ssh3 --mech tar    [--runs 5]
#   manyfiles.sh --stand S2 --transport ssh2 --mech perfile [--limit 100]
#
# mech=tar    : one tar stream over the identical stdin-pipe mechanism for
#               both transports (parity baseline), verified by remote manifest.
# mech=perfile: files copied individually (scp vs ssh3 -f) to expose the
#               per-file/per-session overhead. Reference scenario, not parity.
#               TRAP: ssh3 -f accepts only HOME-RELATIVE remote paths (fork
#               bug: absolute operand paths fail), so perfile copies into
#               ssh3-bench-manyfiles/ under the remote home.
set -euo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

TRANSPORT="ssh3" MECH="tar" RUNS=5 LIMIT=100 OUT="" STAND=""

while [ $# -gt 0 ]; do
    case "$1" in
    --transport) TRANSPORT="$2"; shift 2 ;;
    --mech) MECH="$2"; shift 2 ;;
    --runs) RUNS="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --stand) STAND="$2"; shift 2 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done
[ -n "$STAND" ] || bench::die "--stand is required"
bench::stand "$STAND"
if [ "$TRANSPORT" = "ssh2" ]; then CLIENT_CMD="$(bench::ssh2_cmd)"; else CLIENT_CMD="$(bench::ssh3_cmd)"; fi

MANY_DIR="${MANY_DIR:-/dev/shm/ssh3-manyfiles}"
MANIFEST="$MANY_DIR/manifest.sha"
FILES_DIR="$MANY_DIR/files"
RBASE="$REMOTE_DIR/manyfiles"      # tar mode: absolute tmpfs path
RELBASE="ssh3-bench-manyfiles"     # perfile mode: HOME-relative (bug workaround)
[ -f "$MANIFEST" ] || bench::die "missing $MANIFEST (run bench/genmanyfiles.sh first)"
TOTAL_BYTES=$(du -sb "$FILES_DIR" | cut -f1)
FILE_COUNT=$(find "$FILES_DIR" -type f | wc -l)
bench::csv_init "$OUT" "transport,mech,files,bytes,run,valid,seconds,mbps"

remote_manifest() { # $1 = client cmd, $2 = remote base dir
    bench::exec_remote "$1" "(cd '$2' && find files -type f -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 sha256sum 2>/dev/null)" | tr -d '\r'
}

expected_manifest() { # $1 = file list (abs paths), echoes the sorted manifest
    local f rel
    while IFS= read -r f; do
        rel="${f#"$MANY_DIR"/}"
        (cd "$MANY_DIR" && sha256sum "$rel")
    done < "$1"
}

run_tar() { # $1 = run index; echoes elapsed ns
    local i="$1" t0 t1 rc=0
    t0=$(date +%s%N)
    tar -C "$MANY_DIR" -cf - files |
        bench::exec_remote_stdin "$CLIENT_CMD" "rm -rf '$RBASE' && mkdir -p '$RBASE' && tar xf - -C '$RBASE'" || rc=1
    t1=$(date +%s%N)
    echo $((t1 - t0))
    return $rc
}

run_perfile() { # $1 = run index; echoes elapsed ns; copies $LIMIT files one by one
    local i="$1" t0 t1 rc=0 f
    local list="$LOCAL_TMP/perfile.$i.list"
    find "$FILES_DIR" -type f | LC_ALL=C sort | head -n "$LIMIT" > "$list"
    # ssh3 -f does not create remote directories; paths stay HOME-relative
    bench::exec_remote "$CLIENT_CMD" "rm -rf '$RELBASE' && mkdir -p '$RELBASE/files'" >/dev/null
    t0=$(date +%s%N)
    while IFS= read -r f; do
        local rel="${f#"$MANY_DIR"/}"
        if [ "$TRANSPORT" = "ssh2" ]; then
            eval "scp -q -P $STAND_SSH2_PORT -c $SSH2_CIPHER -o BatchMode=yes '$f' $(printf '%q' "$STAND_SSH2_DEST"):'$RELBASE/$rel'" || rc=1
        else
            eval "$SSH3_BIN $SSH3_ARGS -f '$f' $(printf '%q' "$STAND_SSH3_TARGET"):'$RELBASE/$rel'" || rc=1
        fi
    done < "$list"
    t1=$(date +%s%N)
    echo $((t1 - t0))
    return $rc
}

LOCAL_TMP="$(mktemp -d)"
trap 'rm -rf "$LOCAL_TMP"' EXIT

VALID=0 ATTEMPT=0 MAX_ATTEMPTS=$((RUNS * 2))
while [ "$VALID" -lt "$RUNS" ] && [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ "$MECH" = "tar" ]; then
        NS="$(run_tar "$ATTEMPT")" && BASE="$RBASE" || NS=""
    else
        LIST="$LOCAL_TMP/perfile.$ATTEMPT.list"
        NS="$(run_perfile "$ATTEMPT")" && BASE="$RELBASE" || NS=""
    fi
    if [ -z "$NS" ]; then
        bench::log "run $ATTEMPT failed (transport error)"
        continue
    fi
    if [ "$MECH" = "tar" ]; then
        EXPECT="$MANIFEST"
    else
        expected_manifest "$LIST" > "$LOCAL_TMP/expected.$ATTEMPT.sha"
        EXPECT="$LOCAL_TMP/expected.$ATTEMPT.sha"
    fi
    if diff -q <(remote_manifest "$CLIENT_CMD" "$BASE") "$EXPECT" >/dev/null; then
        SEC="$(awk -v ns="$NS" 'BEGIN{printf "%.3f", ns/1e9}')"
        MBPS="$(awk -v b="$TOTAL_BYTES" -v ns="$NS" 'BEGIN{printf "%.2f", b/1e6/(ns/1e9)}')"
        VALID=$((VALID + 1))
        echo "$TRANSPORT,$MECH,$FILE_COUNT,$TOTAL_BYTES,$ATTEMPT,1,$SEC,$MBPS" | tee -a "${OUT:-/dev/null}"
    else
        bench::log "run $ATTEMPT manifest mismatch — discarded"
    fi
done

bench::exec_remote "$CLIENT_CMD" "rm -rf '$RBASE' '$RELBASE'" >/dev/null 2>&1 || true
bench::log "done: $VALID/$RUNS valid runs ($TRANSPORT $MECH)"
[ "$VALID" -ge "$RUNS" ] || exit 1
