# Security Audit — ssh3 Go server, deep-dive (pass 2)

**Audit date (UTC):** 2026-10-07
**Audited revision:** `ff5ef776dec9ca40a04d90be79c1b3b9c898f915` (`origin/main`, tag `v0.1.27`)
**Auditor:** engineering agent (report-only engagement; no code was changed)
**Predecessor:** `docs/SECURITY_AUDIT_2026-10-06.md` (pass 1, PR #2), audited `00c2f46` / `v0.1.26`.
**Scope:** the ssh3 **Go server** end to end — `cmd/ssh3-server.go`, `server.go`, `channel.go`, `conversation.go`, `server_auth/`, `auth/` verifiers, `util/unix_util`, `cmd/sftp_subsystem.go` + the new `cmd/internal_sftp.go`, forwarding (`cmd/forward_policy.go`, `cmd/dynamic_forward_server.go`, `cmd/reverse_forward_server.go`), server-side message/util parsing, and the timeout/resource-exhaustion posture.
**Method:** line-by-line source review at the revision above, `git grep` sweeps (panic/recover/dial/chown/chroot/exec), comparison against the pass-1 findings, and cheap local dynamic probes with the recovered `go1.26.0` toolchain (read-only, no live attacks, no network peer).
**Out of scope:** Windows files, packaging/release scripts, CI, `internal/interop` harnesses, the C17 (`project/ssh3-c`) tree, the internals of the deliberate `vendor/h3` Rust patch (reviewed only where it meets the server boundary), and the Rust `crates/` server crate beyond a targeted follow-up if budget remains.

> Report-only: **no code was changed anywhere**. Every recommendation below is a proposal.

## Executive summary

*(filled in as sections land — see the commit history of this file; the coverage section states exactly what was and was not reviewed)*

**Headline:** pass 1 audited `v0.1.26`. The tree has since moved to **`v0.1.27`**, which contains an explicit remediation series for the pass-1 server findings (`9cfd185` F-01, `8dc90cc` F-02, `e61aca0` F-03/F-06/F-08, `8872616` F-04, `9a61107` F-05, `634cd64` panic guards, `8807b43` dependency bumps). Pass 2 therefore audits the **fixes themselves**, which is where the remaining risk now lives.

## Pass-1 findings — re-verification at `ff5ef77` (v0.1.27)

Status values: **FIXED** (the reported mechanism is gone), **FIXED-SHALLOW** (the reported symptom is gone but the class survives), **STILL PRESENT**, **CORRECTED** (pass 1 was wrong).

| Pass-1 ID | Pass-1 claim | Status at `ff5ef77` | Evidence |
|---|---|---|---|
| F-01 | `ParseSSHString` allocates from an unbounded peer length | **FIXED** | `util/wire.go:204-222` — `MaxSSHStringLen = 1<<24` (`:204-209`) is checked *before* `make` (`:216`); `channel.go:173-181` now also refuses a peer `maxPacketSize` above the cap. Regression `util/wire_test.go:42-70`, fuzz target `util/fuzz_test.go:12-33`. |
| F-02 | `ParseMessage` panics on an unknown type id | **FIXED** | `message/message.go:213-225` defines `UnknownMessageType`, `:246` returns it instead of `panic`. Tests `message/parse_message_test.go`, fuzz `message/fuzz_test.go`. |
| F-03 | DoS slot leaks on every successful auth → permanent 503 | **FIXED** (see NEW-…) | `server_auth/auth.go:68-74`: acquire moved *before* conversation creation, with an unconditional `defer ReleaseUnauthenticatedConversation()`. |
| F-04 | SFTP jail is lexical, symlink escape as root | **FIXED** for the default mode (see NEW-…) | `cmd/sftp_subsystem.go:74-110` + `cmd/internal_sftp.go:96-116` — default `-sftp-jail chroot` re-execs a child that `chroot(2)`s into the home dir and drops uid/gid before serving. Lexical mode remains available by explicit operator choice. |
| F-05 | No target policy for server-side forwarding | **FIXED-SHALLOW** | `cmd/forward_policy.go` (new `-permit-open`) is wired into `cmd/ssh3-server.go:762-770` (UDP), `:777-785` (TCP), `cmd/dynamic_forward_server.go:270-275`; default is still *unrestricted* (documented as OpenSSH parity). |
| F-06 | DoS cap acquired after the pre-auth work it protects | **FIXED** | `server_auth/auth.go:68` precedes `GetUser` (`:95`) and `GetAuthorizedIdentities` (`:100`). |
| F-07 | `golang-jwt/jwt/v5 v5.0.0` — CVE-2025-30204 | **FIXED** | `go.mod:8` → `v5.3.1` (commit `8807b43`). |
| F-08 | `r.UserAgent()[:100]` slice panic | **FIXED** | `server_auth/auth.go:24-35` — length-checked truncation. |
| F-09 | `VarIntLen`/`AppendVarIntWithLen` latent panic | **STILL PRESENT** (latent, unchanged) | `util/wire.go:198-203` still panics; callers re-enumerated, all bounded. |
| F-10 | `rustls 0.23.37` (Rust) | **FIXED** | `Cargo.lock` → `rustls 0.23.45`. |
| F-11 | Other dependency advisories | **FIXED** (bumps) | `golang.org/x/crypto 0.57.0`, `go-jose/v3 3.0.5`, `golang.org/x/oauth2 0.37.0`. |
| F-12 | Client `Match exec` | **STILL PRESENT (by design, client-side)** | unchanged |
| F-13 | Host-key pin comparison not constant-time | **CONFIRMED INFO** | unchanged; no secret in the compared value |

## New findings (pass 2)

*(pending — sections below, each committed as it lands)*

## Coverage

*(pending)*

*End of report.*
