# Changelog

All notable changes to the **nagual2 fork** of SSH3, starting from the first fork release. Changes that predate the fork — the upstream [`francoismichel/ssh3`](https://github.com/francoismichel/ssh3) project and the Rust-rewrite lineage this repository was built on — are **not** covered here; see the respective upstream sources for those.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); each section maps to a release tag, newest first.

## Unreleased

### Changed
- **GatewayPorts policy for reverse forwarding (`-R`)** (`cmd/reverse_forward_server.go`, `cmd/ssh3-server.go`): wide binds used to be honored with a warning. The server now applies the sshd_config semantics via `-gateway-ports no|clientspecified|yes` / `SSH3_GATEWAY_PORTS`, default `no`: every client-requested non-loopback bind is silently forced back to the loopback exactly as OpenSSH does (an info line names the rewrite), `clientspecified` honors the bind address the client asked for, `yes` binds the wildcard address. The bind reply carries the bound port only, so the change is wire-compatible with old clients. The per-bind wide-bind warning now fires only when a wide bind is actually taken under `clientspecified`/`yes`.
- **Per-user reverse forward limits** (`cmd/reverse_forward_server.go`, `cmd/ssh3-server.go`): the server caps active `-R` listeners per authenticated user (`-max-reverse-forwards` / `SSH3_MAX_REVERSE_FORWARDS`, default 10) across their conversations, on top of the existing per-conversation forwarded-channel bound; a bind over the limit is refused with a readable error on the control channel and the budget slot is returned when the conversation ends.

### Fixed
- **Reverse UDP forwards silently truncated datagrams at the server socket** (`cmd/reverse_forward_server.go`): the `-R .../udp` listener read into a 1500-byte buffer, so larger datagrams were cut at the read and the send then failed with a generic error. Datagrams are now read whole; one that exceeds the QUIC datagram limit of the path is dropped with an explicit warning naming the size and the path limit — the datagram path is lossy by design, but no longer silently truncated.

## [0.1.25] - 2026-10-04

### Fixed
- **Dynamic SOCKS forwarding (`-D`) could not connect at all** (`cmd/dynamic_forward.go`): the SOCKS5 request reader computed one byte too many for every address form. The `+1` that is only correct for the domain form's length byte was applied to IPv4 and IPv6 as well (IPv4 computed as 11 bytes instead of 10, IPv6 as 23 instead of 22), and after reading the domain length byte the final read started over at that byte, re-reading it. A real client's request was therefore never complete: the reader stalled until the 30-second handshake deadline killed the connection, so every `CONNECT` through the proxy timed out. The exact request size is now computed per address form, and the domain payload is read past the already-consumed length byte. Caught by a live loopback smoke test, not by the unit suite: the reader had no test at all, and a regression test now drives real request bytes for all three address forms through `net.Pipe`.
- **`-D` allocated a huge datagram queue per connection** (`cmd/dynamic_forward.go`): the data channel was opened with the 10 MiB channel window constant passed as the *datagrams queue size*, which allocates a channel entry per queue slot (tens of megabytes per SOCKS connection) although the tunnel never carries datagrams. The queue size is now 0, as for the session and reverse-forward channels.

## [0.1.24] - 2026-10-04

### Added
- **`Match` inside `Include` files** (`~/.ssh/config`): `Include` is now expanded by the `Match`-aware pre-parser itself, recursively, before the ssh_config decoder sees the text. Until now any `Match` block reached through an `Include` aborted the decoder and the whole `~/.ssh/config` was thrown away; now the content of an included file goes through the same alias and `Match` filtering as the main file, so an included `Host` or `Match` block behaves exactly as if it had been written inline. Glob patterns in `Include` targets, nested includes, a cyclic-include guard, and a recursion depth limit of 16 are supported. A missing or unreadable include is skipped instead of invalidating the rest of the configuration, and a `Match` parse error now names the included file and the line it actually comes from instead of pointing at the main config.
- **SSHFP host verification (RFC 4255)** (`sshfp.go`, `strict_host_key.go`, `cmd/sshfp_resolver.go`): the type-44 DNS records published for a host are looked up and compared against the real fingerprint of the presented host key. The fingerprint is taken over the DER X.509 host certificate (`cert.Raw`) — ssh3 pins certificates, not raw SSH public keys — and the DNS wire format is built and parsed in-tree, so no third-party resolver is involved. The verification is wired into the client connection path and is reachable from the command line through `-o VerifyHostKeyDNS=...` or the same keyword in `~/.ssh/config`; it is off by default, as in OpenSSH. Accepted values are `no` (also `false`, `off`, empty), `ask`, `yes` (also `true`, `on`) and `yes:algo[,algo...]`, which restricts the lookup to the listed host key algorithms — the short and full public-key names (`rsa`, `ssh-rsa`, `dsa`, `ssh-dss`, `ssh-dsa`, `ecdsa`, `ecdsa-sha2-nistp256/384/521`, `sk-ecdsa-sha2-nistp256`, `ed25519`, `ssh-ed25519`) plus the `sha1` and `sha256` digests. An unknown value or algorithm is rejected up front like any other malformed `-o`. Only a **mismatch** between published records and the presented key can refuse a host: NXDOMAIN, an empty answer, a truncated datagram, a timeout, an unavailable resolver and network errors are all soft skips that leave the known_hosts decision untouched. `ask` does not prompt — a mismatch under `ask` is refused with a warning naming the option that could override it — and with `StrictHostKeyChecking=no` a mismatch only warns and the connection continues. The exchange is bounded by a 2 s deadline (`DefaultSSHFPTimeout`) and the configured servers are queried in order; the lookup runs right after the dial, on the same certificate the known_hosts check used, and `-insecure` skips it along with the rest of host verification. On Windows the resolver configuration lives in the registry rather than in `/etc/resolv.conf`, so the servers are read from the local adapters through `GetAdaptersAddresses`, and an enumeration failure is a soft skip rather than an error. Record algorithms RSA, DSA, ECDSA and Ed25519 are recognised, and both SHA-1 and SHA-256 digest types are computed; RSA, ECDSA and Ed25519 host keys are matched against them.
- **ControlMaster control operations `check` and `stop`** (`client/control.go`, `cmd/controlmaster.go`): both travel over one new control frame that carries the operation name, so the master can grow operations without touching the framing. `check` answers with a status snapshot — pid, uptime, number of active sessions and forwarded channels — which the CLI plumbing prints on stdout before exiting 0; with no master listening it fails with an explicit error and a non-zero exit code. `stop` shuts the master down and waits until the control socket has actually been released, so the path is free and no stale socket is left behind. An operation this build does not know is refused by the master with a readable error instead of hanging. `exit` deliberately stays on the historical `MsgExit` frame so that masters from v0.1.22/v0.1.23 still understand it, and the new operations against such an older master produce a clear "the control master does not support …" error rather than a hang. All three operations are dispatched from the command line, on both the `-control-path` fast path and the normal path, and a value outside the set is rejected up front with the list of supported operations, before any key or known_hosts file is read.
- **Dynamic SOCKS forwarding** (`message/dynamic_forward.go`, `cmd/dynamic_forward_server.go`, `cmd/dynamic_forward.go`, `cmd/cli_flags.go`): the protocol is two channel types. The client opens one `dynamic-forward` control channel carrying a `RequestDynamicForward` announcement, and every connection its SOCKS listener accepts is mirrored to the server as a client-initiated `dynamic-forward-tcp` channel carrying a `DynamicForwardTarget`; the server resolves the address, dials it itself and bridges the channel with the TCP connection. Unlike the `-R` targets, the address may be a hostname — a SOCKS client often only knows a name — and the server is the side that resolves it. Deliberately **no new message-type id** was introduced: `ParseMessage` panics on unknown ids, which would crash older peers, so every payload travels as channel data behind a versioned varint prefix (version 1 + message kind) that an old peer simply never sees. Per connection the server replies with the outcome of the dial, so a resolution or connection failure reaches the SOCKS client as a readable reason; at most 64 `dynamic-forward-tcp` channels may be bridged at once per conversation, and closing the control channel or the conversation tears down every live bridge. On the client side `-D [bind_address:]port` opens the local SOCKS5 listener, the OpenSSH `-D` equivalent: it speaks SOCKS5 *no authentication required* only (it binds a local listener and bridges the connection inside ssh3, so it never sees credentials), supports `CONNECT`, accepts IPv4, IPv6 and domain address types, binds loopback without an address and every interface for `*`, requires IPv6 literals to be bracketed so a bare `::1:1080` is rejected instead of misread, and treats port `0` as a request for an ephemeral bind whose result is logged. `-D` combines with a session or with `-N`, in which case the client starts the channel loop itself.
- **Forced pseudo-terminal (`-t`)**: when there is no local terminal — a pipe, a cron job, a detached start — no PTY is requested and remote full-screen programs refuse to start. `-t` requests one anyway, taking the terminal type from `$TERM` (`xterm` when unset) and the geometry from the local console with an **80x24** fallback when it cannot be queried, which is still better than a bare pipe. `SIGHUP`, `SIGINT`, `SIGQUIT` and `SIGTERM` are relayed into the remote PTY, and on unix `SIGWINCH` becomes a window-change request, so `ssh3 -t user@host top` stays resizable. Windows has no `SIGWINCH` — the console reports a resize as an event rather than a signal — so there the geometry sent with the PTY request holds for the whole session.
- **Subsystem requests (`-s`)**: `-s NAME` asks the server for a subsystem instead of a shell or a command, exactly as `ssh(1)` does. `sftp` is special-cased onto the interactive SFTP client that already lives in the client package, with the command set of `sftp(1)` reduced to what is useful interactively (`pwd`, `ls`, `cd`, `get`, `put`, `mkdir`, `rm`, `rmdir`, `help`, `quit`/`exit`); any other name is sent as a subsystem request on the session channel, and the bundled Go server answers that with *not implemented*, so a free name is only useful against a server that serves subsystems. With `-t` the PTY is requested before the subsystem. `-s` owns the session channel and is rejected at the command line together with `-f`, `-N`, `-forward-agent`, `-R` and a remote command.
- **Alternative configuration file (`-F`)**: `-F PATH` reads a user configuration file other than `~/.ssh/config`, whose path is used verbatim as in OpenSSH, so a relative path stays relative to the current directory. Everything resolved from the configuration — `Host`, `Match`, `Include` — is read from that file in exactly the same way. An unreadable path does not fail the connection: the read error goes to stderr and the configuration is ignored, and a missing file is silently skipped.

## [0.1.23] - 2026-10-04

### Added
- **Reverse forwarding (`-R`)**: `-R [bind:]port[/udp]:target:targetport` asks the server to bind a TCP or UDP listener (loopback by default, wide binds warn, ephemeral ports report the actual port); every accepted connection or datagram comes back over a server-initiated `forwarded-tcp`/`forwarded-udp` channel and is bridged to the client-local target. Targets are validated against the `-R` list, forwarded channels are capped per conversation. Older peers reject the extension gracefully — verified live against a v0.1.22 server and an old client against the new server.
- **`StrictHostKeyChecking`** (`ask|yes|accept-new|no`) with OpenSSH-style priority: CLI flag > `-o` > `~/.ssh/config` > `ask`. Known-host pins are compared on the server certificate after the dial; a changed fingerprint refuses the connection with both `SHA256:` fingerprints in the error; `accept-new` pins automatically; `no` explicitly allows cert changes with a warning.
- **`~/.ssh/config` `Match` support**: criteria `all`, `final`, `host`, `originalhost`, `user`, `localuser`, `exec` (with `!` negation and globs), resolved by a pre-parser that flattens applicable blocks before the vendored ssh_config decoder; configs without `Match` take the untouched fast path.
- `-o Key=Value` is now repeatable and validates known keys; `StrictHostKeyChecking` is accepted as a key.
- `bench/exec-latency.sh`: measures cold one-shot, control-master spawn and warm slave exec latency.

### Changed
- Exec latency: the server no longer sleeps 100 ms before tearing down a non-multiplexed conversation, and the client polls for a spawning control master every 2 ms instead of 100 ms. Cold one-shot exec median on loopback: ~140 ms → ~26 ms; master-spawn first call ~112 ms → ~31 ms; warm slave path unchanged (~9 ms).

### Fixed
- Control master recovers a stale unix socket left behind by a SIGKILLed master instead of failing with `EADDRINUSE` for the full wait deadline (slaves hung 10 s and exited 255).
- Server conversation handlers no longer hang in `AcceptChannel` forever when the QUIC connection dies; the conversation context now derives from the connection.
- The client close path now also closes the QUIC connection, so the server learns of the client's departure promptly.

## [0.1.22] - 2026-10-02

### Added
- `SSH3_ENABLE_PASSWORD_LOGIN` server environment variable as the default for `-enable-password-login`, so systemd `EnvironmentFile` installs can opt into password auth without editing the unit.
- Client flag `-N`: hold the connection open for the forwards without running a session or shell.
- Control master: pty slave sessions now relay terminal resizes (SIGWINCH) and out-of-band signals through the master onto the ssh3 channel; raw-mode input bytes keep flowing through the io stream.
- `~/.ssh/config` extensions: `ServerAliveInterval` tunes the QUIC keepalive (default 1s), `ForwardAgent yes` defaults the `-forward-agent` flag, `ProxyJump` is honored as an alias of the fork's `UDPProxyJump`; `Include` directives resolve via ssh_config v1.2.0.
- Server: graceful shutdown on SIGTERM/SIGINT — stop accepting, drain active connections up to `SSH3_SHUTDOWN_DRAIN` seconds (default 5, `0` closes immediately), exit 0. Under systemd, non-verbose logging emits plain JSON to stderr (journald-friendly, no ANSI colors).

### Changed
- The amd64 release server is now built with CGO and the shadow/crypt password backend compiled in; password auth stays disabled by default and is enabled with `-enable-password-login` or persistently via `SSH3_ENABLE_PASSWORD_LOGIN=1` in `/etc/ssh3/ssh3-server.env`. arm server builds remain key-only (`disable_password_auth`).
- `-control-master` combined with `-proxy-jump` (from the command line or `~/.ssh/config`) is now an explicit error instead of a silent bypass.

### Fixed
- `ssh3 -f` honors server-absolute remote paths (e.g. `/home/user/file`), which previously failed with "file does not exist"; missing remote parent directories are auto-created on single-file uploads.
- The logger mapped the `error` level to `WarnLevel`.

### Performance
- Control master: fast slave path when an explicit `-control-path` is given.

## [0.1.21] - 2026-10-01

### Added
- **Control master** (connection multiplexing): one authenticated QUIC connection shared by many client invocations through a Unix control socket.
  - New flags: `-control-master no|yes|auto`, `-control-path`, `-control-persist no|yes|<seconds>`, `-O exit`.
  - TCP forwarding (`-forward-tcp`), UDP forwarding, and agent forwarding are multiplexed through the master.
  - Master lifecycle: background persistence, idle timeout, clean shutdown via `-O exit`.
  - Median latency of 100 sequential execs drops from ~130 ms (one handshake each) to ~24 ms (a single handshake).
  - Limitations: window changes and signals are not forwarded through the master, `-proxy-jump` is incompatible, Windows is not supported.

### Fixed
- Client half-closes the channel on the truncated-transfer verdict.

### Performance
- Server pools exec stdout/stderr read buffers.

## [0.1.20] - 2026-09-30

### Added
- Key-controlled QUIC bulk-transfer tuning on client and server: `-initial-packet-size`, `-stream-rx-mb`, `-conn-rx-mb`.

### Fixed
- Bounded the post-exit-status PTY drain with FIN and a grace window (PTY Ctrl+D hang).

## [0.1.19] - 2026-09-30

### Changed
- quic-go upgraded from v0.49.0 to v0.63.0 and ported to the new `http3` raw-connection API; release builds use upstream quic-go v0.63.0.

### Fixed
- Dataplane: `WriteData` no longer counts frame-header bytes as stream data.

### Added
- Go wire reference dumper for browser-client test vectors.

## [0.1.18] - 2026-09-30

### Fixed
- The HTTP/3 datagram layer no longer steals ssh3 datagrams.
- The stream hijacker waits for conversation registration.

## [0.1.17] - 2026-09-29

### Changed
- quic-go upgraded from v0.40.1 to v0.59.1, ported to the new `http3` client API.

### Performance
- Zero-copy channel writes: `WriteData` marshals only the frame header.

## [0.1.16] - 2026-09-29

### Added
- Profiling groundwork and the SSH2-vs-SSH3 benchmark suite.

## [0.1.15] - 2026-09-29

### Changed
- Internal refactor: session setup and pumping extracted over arbitrary streams (`io.ReadWriteCloser`).

## [0.1.14] - 2026-09-28

### Added
- File-transfer operand form `user@host:port/url_path:remote_path`.

### Fixed
- The server never truncates command output at session teardown.
- The client keeps reading output after the exit status arrives.

## [0.1.13] - 2026-09-28

### Added
- **File transfer** (`ssh3 -f`) over a dedicated SFTP channel: recursive `-r`, `--continue` resume of interrupted transfers, and `--checksum` SHA-256 verification. The server serves SFTP jailed to the session user's home directory; created files belong to that user.

### Fixed
- The transfer client builds on non-Linux targets.

## [0.1.12] - 2026-09-28

### Added
- `SSH3_USER_HOME` environment override when resolving the session home directory.

### Fixed
- The client waits for the stdin pump before declaring a truncated transfer.

## [0.1.11] - 2026-09-28

### Fixed
- Exit-status delivery hardening for PTY sessions: the real exit status is reported even with pending stdin; the server flushes the exit status before channel teardown; a non-zero exit code is returned when the remote command stops consuming stdin early; signal-killed remote commands yield exit code 255 instead of a panic.
- A clean error is returned instead of a panic on an unreadable private key file.
- Restored the vendored Rust `h3` shim after a vendor sync.

## [0.1.10] - 2026-09-27

### Fixed
- The client half-closes the channel send side on stdin EOF so remote commands terminate.

## [0.1.9] - 2026-09-27

### Added
- Trilingual README (English, Russian, German) with fork documentation.
- CI: Windows client artifacts on every push to `main`; tests run on pushes to `main`.

### Changed
- The shipped systemd unit follows OpenSSH parity: no sandbox directives, `KillMode=process` (active sessions survive daemon restarts; `sudo` inside a session regains full root capabilities).
- Apache-2.0 SPDX headers added to fork-touched files.

## [0.1.8] - 2026-09-26

### Added
- First fork release.
- **Windows client as a first-class citizen:** the Go client compiles for Windows and supports interactive PTY sessions — VT input/output, UTF-8 console code page, real console size, `SIGINT`/`SIGTERM` forwarding, and an 80x24 PTY fallback when the console size cannot be queried.
- Login statistics banner (uptime, load, memory, disk) before the interactive shell prompt.
- Locale forwarding: the server passes `LANG`/`LC_*` from its environment to user shells.
- goreleaser v2 release pipeline: per-tag release archives and a key-only `.deb` package (password authentication compiled out with `-tags disable_password_auth`).
