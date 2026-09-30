#!/usr/bin/env bash
# B10/B11: TCP and UDP forwarding through ssh3 with real-traffic verification
# (see docs/FORWARDING-TESTPLAN.md).
#
# Usage:
#   forwarding.sh --stand S1 [--size-mb 1]
#
# On S1 (client and server share the host) the "remote" services are plain
# local processes; the forwarding path client -> QUIC -> ssh3d -> 127.0.0.1
# is fully exercised.
#
#   Sanity : exec exit status (B4-lite) - base transport must work first.
#   B10 TCP: greeting on the return path, then a FWD_SIZE_MB urandom blob through
#            -forward-tcp; sink captures it, sha256 verified.
#   B11 UDP: UDP_DATAGRAMS distinct datagrams through -forward-udp against an
#            echo service; every echo must match byte-for-byte.
#   DNS    : optional smoke through -forward-udp to the host resolver.
set -uo pipefail
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$BENCH_DIR/lib.sh"

STAND="" FWD_SIZE_MB=1
UDP_DATAGRAMS=20
TCP_LOCAL=13456 TCP_REMOTE=19999
UDP_LOCAL=13455 UDP_REMOTE=19998
DNS_LOCAL=15353
SETUP_WAIT=6 SESSION_KEEP=15

while [ $# -gt 0 ]; do
    case "$1" in
    --stand) STAND="$2"; shift 2 ;;
    --size-mb) FWD_SIZE_MB="$2"; shift 2 ;;
    *) bench::die "unknown flag: $1" ;;
    esac
done
[ -n "$STAND" ] || bench::die "--stand is required"

bench::stand "$STAND"
CLIENT_CMD="$(bench::ssh3_cmd)"

start_forwarding() { # $1 = forward flags, $2 = session keep seconds
    # $1 carries several words ("-forward-tcp 13456/host@port") that must reach
    # the client as separate argv entries; quoting them as one token makes the
    # Go flag parser ignore the option and no forwarder is ever started.
    # The flags must also precede the target: ssh3 parses options with the Go
    # flag package, which stops at the first non-flag argument, so anything
    # placed after user@host/url-path is taken as the remote command instead.
    # shellcheck disable=SC2086
    eval "$SSH3_BIN $SSH3_ARGS $1 $STAND_SSH3_TARGET sleep $2" >/dev/null 2>&1 &
    echo $!
}

wait_port() { # $1 = "tcp|udp", $2 = port
    local proto="$1" port="$2" i
    for i in $(seq 1 20); do
        if ss -l$([ "$proto" = tcp ] && echo tn || echo un) 2>/dev/null | grep -q ":$port "; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

kill_quiet() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }

# --- sanity: base exec must work before any forwarding test -----------------
bench::log "sanity: exec true"
if bench::exec_remote "$CLIENT_CMD" "true" >/dev/null 2>&1; then
    echo "SANITY-exec: PASS"
else
    echo "SANITY-exec: FAIL (base transport broken, forwarding results are void)"
    exit 1
fi

# --- B10: TCP forwarding -----------------------------------------------------
bench::log "B10 TCP forward: 127.0.0.1:$TCP_LOCAL -> 127.0.0.1:$TCP_REMOTE"
cat > /dev/shm/fwd_tcp_sink.py <<'EOF'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19999))
s.listen(1)
c, _ = s.accept()
c.sendall(b"GREETING-FWD-TCP\n")
with open("/dev/shm/fwd-tcp-in.bin", "wb") as f:
    while True:
        d = c.recv(1 << 16)
        if not d:
            break
        f.write(d)
EOF

rm -f /dev/shm/fwd-tcp-in.bin /dev/shm/fwd-tcp-echo.txt
head -c $((FWD_SIZE_MB * 1024 * 1024)) /dev/urandom > /dev/shm/fwd-blob.bin
REF_SHA="$(bench::local_sha /dev/shm/fwd-blob.bin)"

python3 /dev/shm/fwd_tcp_sink.py >/dev/null 2>&1 &
SINK=$!
CLIENT_PID=$(start_forwarding "-forward-tcp $TCP_LOCAL/127.0.0.1@$TCP_REMOTE" "$SESSION_KEEP")
sleep 1

B10="FAIL"
if wait_port tcp "$TCP_LOCAL" && nc -q 3 127.0.0.1 "$TCP_LOCAL" < /dev/shm/fwd-blob.bin > /dev/shm/fwd-tcp-echo.txt 2>/dev/null; then
    GOT_SHA="$(bench::local_sha /dev/shm/fwd-tcp-in.bin 2>/dev/null || true)"
    GREETING="$(head -c 17 /dev/shm/fwd-tcp-echo.txt 2>/dev/null | tr -d '\r')"
    if [ "$GREETING" = "GREETING-FWD-TCP" ] && [ "$GOT_SHA" = "$REF_SHA" ]; then
        B10="PASS"
    fi
fi
echo "B10-TCP: $B10 (greeting+${FWD_SIZE_MB}MiB sha-verified)"
kill_quiet "$SINK"
kill_quiet "$CLIENT_PID"

# --- B11: UDP forwarding -----------------------------------------------------
bench::log "B11 UDP forward: 127.0.0.1:$UDP_LOCAL -> 127.0.0.1:$UDP_REMOTE"
cat > /dev/shm/fwd_udp_echo.py <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19998))
for _ in range(400):
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
EOF
cat > /dev/shm/fwd_udp_send.py <<'EOF'
import socket, sys, time
n = int(sys.argv[1]); port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2.0)
matched = 0
payloads = {i: bytes([i % 251]) * 1024 for i in range(n)}
for i in range(n):
    s.sendto(payloads[i], ("127.0.0.1", port))
got = {}
deadline = time.time() + 4
while len(got) < n and time.time() < deadline:
    try:
        d, _ = s.recvfrom(65535)
    except socket.timeout:
        break
    for i, p in payloads.items():
        if i not in got and d == p:
            got[i] = True
            break
print(f"matched={len(got)}/{n}")
EOF

rm -f /dev/shm/fwd_udp_send.py.out
python3 /dev/shm/fwd_udp_echo.py >/dev/null 2>&1 &
ECHO_PID=$!
CLIENT_PID=$(start_forwarding "-forward-udp $UDP_LOCAL/127.0.0.1@$UDP_REMOTE" "$SESSION_KEEP")
sleep 1

B11="FAIL"
if wait_port udp "$UDP_LOCAL"; then
    python3 /dev/shm/fwd_udp_send.py "$UDP_DATAGRAMS" "$UDP_LOCAL" > /dev/shm/fwd_udp_send.py.out 2>&1
    M="$(grep -o 'matched=[0-9]*/[0-9]*' /dev/shm/fwd_udp_send.py.out | cut -d= -f2)"
    if [ "$M" = "$UDP_DATAGRAMS/$UDP_DATAGRAMS" ]; then
        B11="PASS"
    fi
    bench::log "UDP echo: matched=${M:-none}"
fi
echo "B11-UDP: $B11 ($UDP_DATAGRAMS datagrams echo-verified)"
kill_quiet "$ECHO_PID"
kill_quiet "$CLIENT_PID"

# --- optional DNS smoke through the UDP forward ------------------------------
if command -v dig >/dev/null 2>&1; then
    bench::log "DNS smoke: 127.0.0.1:$DNS_LOCAL -> 127.0.0.53@53"
    CLIENT_PID=$(start_forwarding "-forward-udp $DNS_LOCAL/127.0.0.53@53" "$SESSION_KEEP")
    sleep 1
    DNS="FAIL"
    if wait_port udp "$DNS_LOCAL" && [ -n "$(dig @127.0.0.1 -p "$DNS_LOCAL" debian.org +short +time=3 +tries=1 2>/dev/null | head -1)" ]; then
        DNS="PASS"
    fi
    echo "B11-DNS: $DNS (real resolver query through the tunnel)"
    kill_quiet "$CLIENT_PID"
fi

bench::log "done"
