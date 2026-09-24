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
# Go: upstream vendor/ dir is stale — use module mode
CGO_ENABLED=0 go build -mod=mod -tags disable_password_auth -o bin/ssh3 ./cmd/ssh3
CGO_ENABLED=0 go build -mod=mod -tags disable_password_auth -o bin/ssh3-server ./cmd/ssh3-server
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

Four bugs reproduced in a real transfer session. Each: root cause → fix → regression test.

| # | Bug | Evidence / entry points | Acceptance |
|---|-----|------------------------|------------|
| 1 | Client never signals EOF to the server after local stdin is exhausted. Remote `cat > file` hangs forever; pipelines cannot terminate. | stdin pump goroutine in `client/client.go` (~line 676-692): on `os.Stdin.Read` EOF it just returns; no fin/half-close is sent on the channel | `cat bigfile \| ssh3-client URL "cat > out"` terminates by itself, sha256(out) == sha256(bigfile); interop test covers stdin EOF |
| 2 | Server panics when a client dies mid-transfer: `panic` in `util.VarIntLen` (`util/wire.go:198`) via `message.ExitStatusRequest.Length` (`message/channel_request.go:443`) from `execCmdInBackground` (`cmd/ssh3-server.go:411`). Negative exit status is not length-safe. | kill -9 the client during an active exec; server process dies | server survives abrupt client disconnects; negative/overflowing exit statuses are encoded safely; unit test for `VarIntLen`/`ExitStatusRequest` edge values; fuzz target for message length encoding |
| 3 | Client exits rc=0 even when the transfer was silently truncated (remote `head -c` exited early, channel closed, client reported success) | exec result handling in `client/client.go` and `cmd/ssh3.go` | if the remote side ends early or reports an error, client exits non-zero with a clear stderr message; test with a remote command that exits before consuming all input |
| 4 | Client SIGSEGVs (nil pointer in `jwt.NewWithClaims` ← `BuildJWTBearerToken`, `client_auth.go:331` ← `auth/plugins/pubkey_authentication/client/privkey_auth.go:181`) when the `--privkey` file does not exist | run client with a bogus `--privkey` path | clean error message, exit code 2; nil-key path covered by a unit test |

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
