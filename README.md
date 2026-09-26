<div align="center">
<img src="resources/figures/ssh3.png" style="display: block; width: 60%">
</div>

> [!NOTE]
> SSH3 is still experimental, and the protocol name may still change. The protocol remains SSH-style session and channel semantics carried over QUIC and HTTP/3 Extended CONNECT, but the implementation and surrounding product surface are still evolving.

# SSH3 over HTTP/3
**English** | [Русский](README.ru.md) | [Deutsch](README.de.md)

SSH3 maps RFC 4254-style remote session semantics onto QUIC, TLS 1.3, and HTTP/3 Extended CONNECT. The project aims to preserve familiar SSH workflows while adding HTTP-native authentication and QUIC-native transport features such as datagram forwarding.

This repository currently contains two implementations:

- The original Go client and server in [`cmd/ssh3`](cmd/ssh3) and [`cmd/ssh3-server`](cmd/ssh3-server)
- An in-progress Rust rewrite in [`crates/`](crates)

> [!WARNING]
> Do not treat either implementation as production-hardened. The protocol and code are still under active development, and the Rust rewrite is focused on correctness and interoperability first, not product completeness.

## About the nagual2 fork
This fork focuses on making the Go implementation a practical daily driver:

- **Windows client is a first-class citizen.** Since v0.1.8 the client compiles for Windows and supports interactive PTY sessions: VT input/output, UTF-8 console code page, real console size, `SIGINT`/`SIGTERM` forwarding, and a 80x24 PTY fallback when the console size cannot be queried.
- **Key-only server packaging.** The release `.deb` ships a systemd service (`ssh3-server.service`, UDP 443, secret URL path) built with `-tags disable_password_auth`: password authentication is compiled out, no OIDC is configured, and the post-install script generates a self-signed ed25519 certificate with IP/DNS SANs.
- **Login stats banner.** Interactive sessions print uptime, load, memory, and disk statistics before the shell prompt (`exec` requests are not affected).
- **Locale and shell fixes.** The server forwards `LANG`/`LC_*` from its systemd environment to user shells and starts the account's real login shell from `/etc/passwd` instead of a hardcoded `/bin/sh`.
- **CI.** Every `v*` tag produces release archives and a `.deb` via goreleaser; every push to `main` produces Windows client artifacts.

## Download & Install
Grab the assets from the [latest release](https://github.com/nagual2/ssh3/releases/latest):

| File | Purpose |
| --- | --- |
| `ssh3_client_<ver>_windows_amd64.zip` | Windows client (`ssh3.exe`) |
| `ssh3_client_<ver>_<os>_<arch>.tar.gz` | Client for Linux, macOS, FreeBSD, OpenBSD |
| `ssh3_server_<ver>_linux_<arch>.tar.gz` | Linux server binaries |
| `ssh3_<ver>_amd64.deb` | Server + client package for Debian/Ubuntu/Mint (systemd service, key-only auth) |

Install the Debian package:

```bash
sudo dpkg -i ssh3_0.1.8_amd64.deb
```

The service listens on UDP 443 under the secret URL path `/ssh3-term`. Configuration lives in `/etc/ssh3/ssh3-server.env` (log file and level, `LANG`), the systemd unit in `/usr/lib/systemd/system/ssh3-server.service`, and a self-signed ed25519 certificate with IP/DNS SANs is generated in `/etc/ssh3/` on install if missing.

## Windows client notes
- Flags (such as `-privkey`) must come **before** the positional URL: Go's flag parser stops at the first positional argument.
- The console is switched to UTF-8 and VT processing for the session and restored on exit. Use a Unicode-capable font (Consolas, Lucida Console).
- There is no `/dev/tty` on Windows, so the interactive TOFU prompt cannot run: pin the server certificate in `%USERPROFILE%\.ssh3\known_hosts` (`host:port/path x509-certificate <base64 DER>`), or use `-insecure` consciously.
- SSH agent forwarding is unavailable (unix socket only); window resize is not forwarded (no SIGWINCH equivalent).

## Status
The Go implementation is still the broadest end-user CLI surface. The Rust workspace now covers the protocol core, QUIC/HTTP/3 bootstrap, auth, session handling, PTY shells, resize and signal forwarding, forwarding runtimes, and real Rust<->Go interoperability tests.

The Rust side is no longer just a codec experiment. It includes working client and server binaries, but some operational features are still Go-only today.

## Feature Status
| Capability | Go CLI/server | Rust workspace | Notes |
| --- | --- | --- | --- |
| QUIC + HTTP/3 SSH3 transport | Yes | Yes | Rust uses `quinn` plus a patched vendored `h3` crate. |
| Session shell and exec | Yes | Yes | Covered by unit and real-binary interop tests. |
| PTY shell, resize, and signal forwarding | Yes | Yes | Real-binary resize and signal interop are covered in both directions. Windows clients get a PTY with a fixed 80x24 fallback geometry. |
| Public-key auth | Yes | Yes | Ed25519, P-256, and RSA are covered. |
| Password auth | Yes | Yes | Go password auth depends on platform support for the system password backend. Release packages are built with `-tags disable_password_auth`. |
| OpenID Connect auth | Yes | Yes | Tokens are now bound to the SSH3 conversation via nonce checking. |
| SSH agent auth | Yes | Yes | |
| SSH agent forwarding | Yes | Yes | Unix sockets only; not available from Windows clients. |
| Direct TCP forwarding | Yes | Yes | Rust runtime supports it; Rust CLI does not yet expose forwarding flags. |
| Direct UDP forwarding | Yes | Yes | Rust runtime supports it; Rust CLI does not yet expose forwarding flags. |
| Proxy jump | Yes | No | Currently Go-only. |
| Secret URL path / hidden server path | Yes | No | Currently Go-only. |
| Public certificate automation | Yes | No | Go server supports Let's Encrypt flows; Rust server is self-signed only today. |

## Repository Layout
- [`cmd/ssh3`](cmd/ssh3): original Go client binary
- [`cmd/ssh3-server`](cmd/ssh3-server): original Go server binary
- [`crates/ssh3-proto`](crates/ssh3-proto): wire format, messages, and forwarding headers
- [`crates/ssh3-core`](crates/ssh3-core): conversation and channel runtime
- [`crates/ssh3-quinn`](crates/ssh3-quinn): QUIC bindings
- [`crates/ssh3-h3`](crates/ssh3-h3): HTTP/3 bootstrap and CONNECT handling
- [`crates/ssh3-auth`](crates/ssh3-auth): public-key, password-adjacent helpers, and OIDC verification
- [`crates/ssh3-client`](crates/ssh3-client): Rust client library and binary
- [`crates/ssh3-server`](crates/ssh3-server): Rust server library and binary
- [`internal/interop`](internal/interop): Go helpers used by the Rust real-binary interop suite

## Building
### Rust
Use a recent stable Rust toolchain.

```bash
cargo build --workspace
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

Current Rust CLI surfaces:

```text
$ cargo run -p ssh3-client -- --help
Usage: ssh3-client [OPTIONS] <URL> [COMMAND]...

$ cargo run -p ssh3-server -- --help
Usage: ssh3-server [OPTIONS]
```

For the Rust client, prefer file-backed secret flags such as `--password-file`, `--bearer-token-file`, and `--oidc-client-secret-file` over passing secrets directly on the command line. File-backed secrets are less likely to leak through shell history, process listings, and CI logs.

### Go
Use Go 1.21 or newer. The repository carries a vendored Rust `h3` crate (the `:protocol=ssh3` shim) without a Go `vendor/modules.txt`, so keep Go in module mode:

```bash
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o ssh3 ./cmd/ssh3
CGO_ENABLED=0 GOFLAGS=-mod=mod go build -tags disable_password_auth -o ssh3-server ./cmd/ssh3-server
```

The release and CI builds use `CGO_ENABLED=0` with `-tags disable_password_auth`, which removes password authentication from the binary entirely. If you want password auth on Linux, build with CGO enabled and without the tag:

```bash
CGO_ENABLED=1 GOFLAGS=-mod=mod go build -o ssh3-server ./cmd/ssh3-server
```

## Quickstart
### Local Rust server + Rust client
The Rust server currently starts with a self-signed certificate, so the client example below uses `--insecure`.

Start a local server:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Connect with a private key:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Run a remote command instead of requesting a shell:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

### Go server for public-facing deployment features
If you need the current public-certificate automation, secret URL path, proxy jump, or forwarding CLI surface, use the Go binaries today.

Example Go server with a public certificate:

```bash
ssh3-server -generate-public-cert my-domain.example.org -url-path /ssh3
```

Example Go client:

```bash
ssh3 -privkey ~/.ssh/id_ed25519 username@my-domain.example.org/ssh3
```

For the release server, connect with:

```bash
ssh3 max@my-server.example.org/ssh3-term -privkey ~/.ssh/id_ed25519
```

## Authentication
### Public key
Rust client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

The server reads `~/.ssh3/authorized_identities` or the standard `~/.ssh/authorized_keys` of the target user.

### SSH agent
Rust client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  https://127.0.0.1:4433/ssh3-term
```

To forward the local agent into the remote session:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  --forward-agent \
  https://127.0.0.1:4433/ssh3-term
```

### Password
Enable password login on the server:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --enable-password-login
```

Then connect with the client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --password-file /path/to/password.txt \
  https://127.0.0.1:4433/ssh3-term
```

Note: release packages are compiled with `-tags disable_password_auth`; this path only exists in custom builds.

### OpenID Connect
Rust client OIDC uses flags rather than a config file:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --use-oidc https://issuer.example \
  --oidc-client-id your-client-id \
  --oidc-client-secret-file /path/to/oidc-client-secret.txt \
  https://127.0.0.1:4433/ssh3-term
```

Authorized OIDC identities can be listed in `authorized_identities` alongside public keys:

```text
oidc <client_id> <issuer_url> <email>
```

## Testing
The Rust workspace is the primary verification path in this repository.

Run the full Rust suite:

```bash
cargo test
```

Run the deepest Rust/Go interoperability matrix:

```bash
cargo test -p ssh3-client
```

That interop suite exercises real Rust and Go binaries against each other, including:

- Exec and shell sessions
- PTY allocation, resize, and signal forwarding
- Public-key, password, and OIDC auth
- SSH agent auth and agent forwarding
- TCP and UDP forwarding

When running Go commands directly, keep the toolchain in module mode because of the vendored Rust shim:

```bash
GOFLAGS=-mod=mod go build ./...
```

## Known Gaps
- The Rust server is intentionally minimal today: self-signed certificates only, no secret URL path, and no public certificate automation.
- The Rust CLI does not yet expose TCP forwarding, UDP forwarding, or proxy jump flags even though the underlying runtime is implemented and tested.
- The vendored `h3` patch is a deliberate compatibility shim for arbitrary `:protocol=ssh3` handling and still needs cleanup.
- The Windows client has no SSH agent forwarding and does not forward window resizes; the first connection to a self-signed server requires a pinned certificate in `known_hosts` because the interactive TOFU prompt needs a Unix-style tty.

## Security
SSH3 is promising, but this project still needs substantial review before it should be trusted in production. The protocol surface combines TLS 1.3, QUIC, HTTP authorization, and SSH-style channel semantics, so the right standard is a long period of review and interoperability hardening, not “it seems to work on my machine”.

Use it in labs, CI, private environments, and interop experiments. Do not rely on it yet as a drop-in production replacement for OpenSSH.
