# Changelog

All notable changes to the **nagual2 fork** of SSH3, starting from the first fork release. Changes that predate the fork — the upstream [`francoismichel/ssh3`](https://github.com/francoismichel/ssh3) project and the Rust-rewrite lineage this repository was built on — are **not** covered here; see the respective upstream sources for those.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); each section maps to a release tag, newest first.

## [Unreleased]

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
