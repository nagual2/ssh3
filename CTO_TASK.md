# CTO Task: Bring SSH3 to OpenSSH (SSHv2) parity

> Task brief for an autonomous engineering agent working in this repository.
> Fork lineage: `nagual2/ssh3` ← `MatiasHiltunen/ssh3` (+13 commits, Rust rewrite) ← upstream `francoismichel/ssh3` (dormant since 2024-09-04, HEAD `5b4b242`).

## 1. Mission

Turn this SSH3 implementation into a transport that can be used as a **daily driver on private infrastructure** and, eventually, as a credible alternative to OpenSSH. Work proceeds in stages; each stage is independently shippable. Do not start a later stage before the previous one is green.

## 2. Current state (verified 2026-09-24)

What already works (do not re-litigate, build on it):

- Go client/server (`cmd/ssh3`, `cmd/ssh3-server`): pubkey auth (ed25519/P-256/RSA), shell, exec, PTY, OIDC, agent forwarding, TCP/UDP forwarding CLI, proxy jump, Let's Encrypt automation.
- Rust workspace (`crates/`): protocol core, QUIC/H3 bootstrap, auth, client+server binaries, real-binary Rust↔Go interop test suite (`cargo test -p ssh3-client`).
- `vendor/h3` is a **deliberate** `[patch.crates-io]` shim for `:protocol=ssh3` extended CONNECT; verified byte-identical to hyperium/h3 v0.0.8 except the shim. Do not swap it for upstream h3 until datagram/extended-CONNECT support lands upstream.
- Security audit of the full delta vs upstream came back clean (static review of all `unsafe`/`exec`/network/file access points, supply-chain check of go.mod/go.sum/Cargo.lock — no git deps, all crates.io).
- LAN benchmark (512 MiB random, WSL client → Atom x5-Z8350 server, USB btrfs destination): SSH3 push ≈ 28.5 MB/s, pull ≈ 24 MB/s; scp baseline ≈ 42.5 MB/s. Single QUIC stream, userspace crypto on a CPU without AES-NI.

Build notes (reproduce before hacking):

```bash
# Go: vendor/ is a synced Go module tree since 2026-09-27 — plain
# `go build ./...` / `go test ./...` work; -mod=mod is no longer needed.
# TRAP: `go mod vendor` deletes vendor/h3 (see §2 shim note above).
# If nuked, restore with: git checkout dba4017 -- vendor/h3
CGO_ENABLED=0 go build -tags disable_password_auth -o bin/ssh3 ./cmd/ssh3
CGO_ENABLED=0 go build -tags disable_password_auth -o bin/ssh3-server ./cmd/ssh3-server
# Server needs a writable log target: env SSH3_LOG_FILE=/tmp/ssh3.log (default /var/log/ssh3.log fails unprivileged)
```

## 3. Ground rules

1. Tests first (TDD). The Rust interop suite is the primary verification path; add a regression test for every bug fix below.
2. Small PRs, conventional commits, one concern per PR.
3. No new dependencies without justification in the PR description; Go deps must stay in go.mod/go.sum, Rust in Cargo.lock (registry sources only — no git dependencies).
4. No telemetry, no network calls outside the SSH3 protocol semantics.
5. Prefer file-backed secrets (`--password-file`, `--bearer-token-file`) over CLI args in new code.
6. Both implementations must keep building after every PR: Go with the flags above, Rust with `cargo build --workspace`.

## 4. Stage 1 — Reliability (P0, do first)

Four bugs reproduced in a real transfer session; bug 5 found 2026-09-30. Each: root cause → fix → regression test.

| # | Bug | Evidence / entry points | Acceptance |
|---|-----|------------------------|------------|
| 1 | Client never signals EOF to the server after local stdin is exhausted. Remote `cat > file` hangs forever; pipelines cannot terminate. | stdin pump goroutine in `client/client.go` (~line 676-692): on `os.Stdin.Read` EOF it just returns; no fin/half-close is sent on the channel | `cat bigfile \| ssh3-client URL "cat > out"` terminates by itself, sha256(out) == sha256(bigfile); interop test covers stdin EOF |
| 2 | Server panics when a client dies mid-transfer: `panic` in `util.VarIntLen` (`util/wire.go:198`) via `message.ExitStatusRequest.Length` (`message/channel_request.go:443`) from `execCmdInBackground` (`cmd/ssh3-server.go:411`). Negative exit status is not length-safe. | kill -9 the client during an active exec; server process dies | server survives abrupt client disconnects; negative/overflowing exit statuses are encoded safely; unit test for `VarIntLen`/`ExitStatusRequest` edge values; fuzz target for message length encoding |
| 3 | Client exits rc=0 even when the transfer was silently truncated (remote `head -c` exited early, channel closed, client reported success) | exec result handling in `client/client.go` and `cmd/ssh3.go` | if the remote side ends early or reports an error, client exits non-zero with a clear stderr message; test with a remote command that exits before consuming all input |
| 4 | Client SIGSEGVs (nil pointer in `jwt.NewWithClaims` ← `BuildJWTBearerToken`, `client_auth.go:331` ← `auth/plugins/pubkey_authentication/client/privkey_auth.go:181`) when the `--privkey` file does not exist | run client with a bogus `--privkey` path | clean error message, exit code 2; nil-key path covered by a unit test |
| 5 | **(2026-09-30, P0, fixed 2026-09-30)** Interactive PTY session: Ctrl+D (0x04 typed in a raw-mode console) makes the remote shell exit, but the client process never terminates. Client 0.1.18/0.1.19; verified NOT a server-build issue (hang reproduces against both release and HEAD servers on LAN latency; clean on loopback latency). **Full brief: `docs/BUG-PTY-CTRLD-HANG.md`.** | Post-ExitStatus drain loop `client/session_pump.go:141-155` waits for a server-side channel EOF the server only sends after the client's send half closes; raw console stdin never EOFs. PTY wiring: `client/client.go:600-648`. Fixed client-side: on ExitStatus a PTY session FINs its send half and bounds the drain with `ptyExitGrace` + `CancelRead` (`client/session_pump.go`) | `printf '\x04'` into a PTY session via `script -qc` terminates the client on its own against a LAN-latency server (see brief §6); exec-mode EOF/truncation semantics (bugs 1/3) unchanged; regression tests `TestPumpPtyExitDrainIsBounded`/`TestPumpPtyExitHalfClosesChannel` |

Definition of done for Stage 1: full `cargo test` + Go test suite green; the four scenarios above covered by automated tests; manual 512 MiB transfer stress (repeat 10×, including abrupt kills) leaves the server alive and all completed transfers bit-identical.

## 5. Stage 2 — Real file transfer (P1)

Today "copy" is a stdin-pipe trick. Implement a proper file transfer channel:

1. An SFTP-like subsystem multiplexed over an SSH3 channel (reuse the existing channel/request machinery; evaluate embedding a Go SFTP server implementation such as `github.com/pkg/sftp` over an `io.ReadWriteCloser` adapter to the channel — justify the dependency).
2. Client UX: `ssh3 -f <local> <user@host:path>` upload/download, directory recursion, resume (`--continue`), preserve mode/timestamps (best effort), progress output, `--checksum` verification mode.
3. Integrity by default: final hash comparison for transfers above a size threshold, mismatch → non-zero exit.
4. Optional: expose the same over the Rust client CLI once the channel protocol is settled (Rust first as a library consumer, CLI flags second).

Acceptance: copy a 1 GiB tree with subdirectories over a lossy link (simulate with `tc netem` 2% loss), resume works, checksums match, no server panics under interruption.

## 6. Stage 3 — Daily-driver features (P2)

1. Host key verification story: TOFU mode writing QUIC/TLS certificates to `~/.ssh3/known_hosts` (format already parsed by the client — `ssh3.ParseKnownHosts`), `strict` and `--insecure` explicitly logged as dangerous. Pin by certificate fingerprint, support SSHFP-like DNS records as stretch goal.
2. Rust CLI parity with Go: port forwarding flags (TCP/UDP direct + reverse), proxy jump, secret URL path.
3. `~/.ssh/config`: extend parsing to `ProxyJump`, `ForwardAgent`, `ServerAliveInterval`, `Include`, `Match` (currently only Hostname/User/Port/IdentityFile).
4. Keepalives and connection migration sanity: NAT rebinding should not kill a session (QUIC gives this for free only if transport config enables migration — verify and test).
5. Server ops: graceful shutdown on SIGTERM (finish active channels, configurable drain), systemd hardening docs (unit example with `ProtectSystem`, `PrivateTmp`), log to journald-friendly output.

## 6a. Stage 1.5 — Data-path performance — P1, pilot-prioritized 2026-09-29

Close the loopback bulk-transfer gap exposed by the R3 benchmark
(docs/BENCH-2026-09-29.md): SSH3 130 MB/s vs OpenSSH 365–488 MB/s (×2.8–3.7).

Diagnosis constraints (verified 2026-09-29): AES-NI is already in use (Go
crypto/aes hardware path on the bench CPU) — the cost is the userspace QUIC
packet pipeline (per-packet syscalls, buffer copies, single connection loop),
not the AES math. kTLS/kernel crypto is impossible for QUIC by protocol design.
quic-go is pinned at v0.40.1 (2024-01); QUIC transport tuning is absent.

Increments (measurement-driven; re-run B1/B2 after each):

| # | Increment | Acceptance |
|---|-----------|------------|
| 1 | Profile harness: pprof hooks (opt-in flag) on client/server; quic-go-only microbench to separate transport ceiling from ssh3-layer overhead | hotspot profile committed to docs/ |
| 2 | Transport tuning: GSO verification/activation, datagram size, flow-control windows and buffer sizes for bulk | B1 loopback improvement, each knob measured separately |
| 3 | quic-go upgrade to current release, re-basing the deliberate vendor/h3 `:protocol=ssh3` shim | full Go + Rust interop suites green; B1/B2 re-measured |
| 4 | (conditional on profile) ssh3-layer copies/buffering fixes | B1 loopback ≥ 250 MB/s; LAN within 15% of scp |

Non-goal: kernel TLS / crypto offload (impossible for QUIC). For no-AES-NI
targets (Atom), evaluate ChaCha20-Poly1305 cipher agreement instead.

## 6b. Stage 3.5 — Connection multiplexing (ControlMaster) — P2, pilot-prioritized 2026-09-28

ssh2-style ControlMaster for the Go client: one authenticated QUIC connection shared by many
CLI invocations through a Unix-domain-socket control channel. Client-only; works against a
stock ssh3-server.

Design (verified against the code on 2026-09-28):

| # | Element | Decision |
|---|---------|----------|
| 1 | Master | First invocation with `ControlMaster=auto/yes` + `ControlPath` performs connect+auth, then serves a UDS socket instead of running one session; `ControlPersist` keeps it in the background with an idle timeout |
| 2 | Mux protocol | Own minimal versioned framing (not OpenSSH-wire compatible): `HELLO{v}`, `OPEN_SESSION{argv,env,pty,agent}`, `OPEN_FORWARD_TCP/UDP`, `EXIT`; UDS perms 0600, path `~/.ssh3/cm-<user>@<host>:<port>`; SO_PEERCRED uid check on Linux |
| 3 | Slave | Later invocations connect to the UDS, request a session; master opens a channel via `Client.OpenChannel("session", …)` on the live connection and bridges bytes both ways |
| 4 | Refactor | Extract `RunSession`'s stdio pumping into a variant over `io.ReadWriteCloser` so the master can serve slave sessions without owning process stdio |
| 5 | Keepalive | Master-owned keepalives against the QUIC idle timeout; connection migration is a free win |
| 6 | Portability | Windows AF_UNIX works but is a separate test track; Rust client adopts the same protocol later (parity, non-blocking) |

Increments (TDD, each independently shippable):

| # | Increment | Acceptance |
|---|-----------|------------|
| 1 | Session pump refactor over `io.ReadWriteCloser` | no behavior change; existing suites green |
| 2 | Mux framing codec | unit tests: round-trip, version mismatch, garbage input |
| 3 | Master + slave session bridging | integration test on loopback: slave session executes through master |
| 4 | `ControlPersist`, idle timeout, `-O exit` control ops | master survives client exit; clean teardown |
| 5 | Forwards through master | local TCP/UDP forward via slave request works |
| 6 | Config plumbing (`-o ControlMaster/ControlPath/ControlPersist`) | flags documented in all READMEs |

Definition of done: 100 sequential `ssh3 host true` — with a master: 1 handshake total and
per-exec time ≤ 30% of the cold path; without: 100 handshakes. No new dependencies.

## 7. Stage 4 — Hardening & ecosystem (P3)

1. External security review checklist: token replay across conversations (jti binding exists — prove it), header injection in CONNECT, QUIC amplification, DoS limits per conversation (MaxStartups analog), brute-force lockout.
2. PAM-based password auth (replace direct shadow reading; enables non-root servers and 2FA).
3. FIDO2/hardware keys (`ed25519-sk` semantics), SSH certificate authority model.
4. Packaging: distro packages (deb/rpm), release pipeline without third-party toolchain downloads (current upstream release CI pulls musl toolchain from musl.cc — replace with reproducible local builds).
5. Docs: deployment guide (self-signed + Let's Encrypt paths), threat model document.

## 8. Non-goals

- Do not chase X11 forwarding or interactive agent features before Stage 3 is done.
- Do not attempt WireGuard/Tailscale-style VPN features.
- Do not break the wire protocol without bumping and documenting a protocol version — interop with the Go implementation must be maintained at every commit.

## 9. Reporting

Every PR states: which stage/task it belongs to, what tests prove it, and any deviations from this brief with rationale. If a task turns out to be infeasible as specified, stop and document why instead of silently shipping something weaker.
