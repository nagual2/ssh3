#!/usr/bin/env python3
"""Interactive PTY echo RTT benchmark (TESTPLAN B5, metric M4).

Spawns the client under a real PTY (the ssh3 client requests a remote PTY
automatically when stdin is a tty), runs `cat` on the remote side and measures
the round trip of unique ping lines echoed back by the remote line discipline.

Usage:
  CLIENT_CMD="ssh -c aes128-gcm@openssh.com -o BatchMode=yes user@host" \
      pty_rtt.py --iters 100 [--label ssh2] [--out rtt.csv]

Stdout: one CSV line per iteration (label,iter,ms) plus a summary on stderr.
"""

import argparse
import math
import os
import pty
import select
import signal
import statistics
import sys
import time


def percentile(sorted_values: list[float], q: float) -> float:
    idx = max(0, math.ceil(q * len(sorted_values)) - 1)
    return sorted_values[idx]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--client-cmd", default=os.environ.get("CLIENT_CMD", ""),
                    help="client command line without remote command; remote 'cat' is appended "
                         "(falls back to CLIENT_CMD env var)")
    ap.add_argument("--iters", type=int, default=100)
    ap.add_argument("--timeout", type=float, default=10.0, help="per-iteration timeout, seconds")
    ap.add_argument("--label", default="pty")
    ap.add_argument("--out", default="", help="append CSV lines to this file")
    args = ap.parse_args()
    if not args.client_cmd:
        ap.error("--client-cmd is required (or set CLIENT_CMD env var)")

    out_f = open(args.out, "a") if args.out else None
    if out_f and out_f.tell() == 0:
        out_f.write("label,iter,ms\n")

    pid, fd = pty.fork()
    if pid == 0:  # child: client inherits the PTY as stdin/stdout/stderr
        os.execl("/bin/bash", "bash", "-c", f"{args.client_cmd} cat")
        os._exit(127)

    def kill_child() -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass

    buf = b""

    def drain_quiet(quiet: float, hard: float) -> None:
        """Read until the stream is silent for `quiet` seconds (startup banner)."""
        nonlocal buf
        last_data = time.monotonic()
        start = last_data
        while time.monotonic() - last_data < quiet:
            if time.monotonic() - start > hard:
                break
            r, _, _ = select.select([fd], [], [], 0.2)
            if fd not in r:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            buf += chunk
            last_data = time.monotonic()
        buf = b""

    drain_quiet(quiet=1.0, hard=args.timeout)

    samples: list[float] = []
    timeouts = 0
    for i in range(args.iters):
        token = f"ping-{i}-{time.monotonic_ns()}"
        payload = (token + "\n").encode()
        buf = b""
        t0 = time.monotonic()
        os.write(fd, payload)
        ok = False
        while time.monotonic() - t0 < args.timeout:
            if token.encode() in buf:
                ok = True
                break
            r, _, _ = select.select([fd], [], [], 0.5)
            if fd not in r:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
        if not ok:
            timeouts += 1
            print(f"no PTY echo for iteration {i}", file=sys.stderr)
            if timeouts >= 3 and not samples:
                kill_child()
                print("PTY echo never arrived: remote PTY not supported/broken", file=sys.stderr)
                return 2
            continue
        dt_ms = (time.monotonic() - t0) * 1000.0
        samples.append(dt_ms)
        line = f"{args.label},{i},{dt_ms:.2f}"
        print(line)
        if out_f:
            out_f.write(line + "\n")
            out_f.flush()

    kill_child()
    if out_f:
        out_f.close()

    if not samples:
        print("no successful iterations", file=sys.stderr)
        return 1
    s = sorted(samples)
    print(
        f"[bench] pty_rtt {args.label}: "
        f"min={s[0]:.1f}ms p50={percentile(s, 0.5):.1f}ms "
        f"p95={percentile(s, 0.95):.1f}ms max={s[-1]:.1f}ms n={len(s)} "
        f"(timeouts={timeouts})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
