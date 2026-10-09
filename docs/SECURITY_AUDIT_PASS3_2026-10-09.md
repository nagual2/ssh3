# Security audit — pass 3 (fix verification)

**Repo:** `nagual2/ssh3-go` · **Audited HEAD:** `8725d65` (`origin/main`, v0.1.28) · **Pass-2 baseline:** `ff5ef77` (v0.1.27)
**Audit date (UTC):** 2026-10-09 · **Auditor:** engineering agent (report-only engagement; **no code was changed**)
**Predecessors:** `docs/SECURITY_AUDIT_2026-10-06.md` (pass 1, `00c2f46`), `docs/SECURITY_AUDIT_SERVER_PASS2_2026-10-07.md` (pass 2, `ff5ef77`).

**Scope of this pass.** The owner reports the pass-2 findings as fixed. This pass therefore audits *the fixes*: it verifies each pass-2 item against the remediation commit, hunts for regressions introduced by that commit, and sweeps only the changed code for new defects. Severity uses the same scale as pass 2; exploit conditions state pre-auth vs post-auth.

**Method.** `git log --oneline ff5ef77..origin/main` + `git show 73aecac` (diff-driven); line-by-line reading of every hunk of the remediation commit and of the code it touches at `8725d65`; targeted `git grep` sweeps for the channel-type table, the buffers sized from `MaxPacketSize()`, the session map, the sftp spawn path and the quic config; cheap local dynamic probes with a recovered `go1.26.0` toolchain. No live attacks, no end-to-end run.

---

## 1. Change set since the pass-2 baseline

```
8725d65 docs(changelog): restore newest-first section ordering
98f48da chore(release): bump software version to 0.1.28
73aecac fix(security): close the pass-2 audit findings (S2-01..S2-07)
c4aea26 feat(sftp): pipeline recursive transfers, 2000 files 25.9s -> 1.3s
10f72d1 Merge pull request #3 from nagual2/docs/security-audit-pass2
```

| Commit | Nature | Maps to |
|---|---|---|
| `10f72d1` | merge (pass-2 report) | docs only — no code |
| `c4aea26` | **feature** (sftp client pipelining), `cmd/sftp_client.go` +262/-30, `cmd/sftp_client_test.go` +153 | not a remediation; client-side; swept in §4 |
| `73aecac` | **remediation**: `channel.go`, `conversation.go`, `server.go`, `util/util.go`, `cmd/ssh3-server.go`, `cmd/channel_budget.go` (new), `cmd/forward_policy.go`, `cmd/reverse_forward_server.go`, `cmd/sftp_subsystem.go`, tests | S2-01…S2-07 |
| `98f48da` | release bump (0.1.28), `version.go` | none |
| `8725d65` | changelog ordering | none |

Files the remediation did **not** touch, which matters for the questions asked: `cmd/internal_sftp.go` (the chroot + drop_child code) is byte-identical to `ff5ef77` — pass-2's line-by-line verification of it therefore still stands at this HEAD and was not re-walked. `client/client.go`, `cmd/dynamic_forward_server.go`, `cmd/dynamic_forward.go`, `cmd/sftp_client.go` (except the `c4aea26` feature) are unchanged.

---

## 2. Pass-2 finding status at `8725d65`

| ID | Pass-2 claim | Status | Evidence at `8725d65` |
|---|---|---|---|
| **S2-01** | Peer-chosen `maxPacketSize` sizes the endpoint's read buffers | **FIXED** | `channel.go:163-170` (`clampPeerMaxPacketSize` = `min(peer, local)`); applied on the **server** inbound path `server.go:171-182` before `ChannelInfo` is built (`:194-206`), and on the **client** inbound path `conversation.go:294`. The server's local value is its own `NewServer(30000, …)` (`cmd/ssh3-server.go:1245` → `server.go:55-58`). All buffers derived from it move accordingly: `cmd/ssh3-server.go:249,357,830`, `cmd/dynamic_forward_server.go:388`, `client/client.go:129,204`, `client/session_pump.go:91`. Residual: the clamp is a ceiling without a floor (see **P3-02**). |
| **S2-02** | Unbounded channels/subsystems per conversation; `runningSessions` never pruned; process per sftp channel | **PARTIALLY FIXED** | Channel budget: `cmd/channel_budget.go:1-84` (counting semaphore, `0` = unlimited), instantiated **per conversation** at `cmd/ssh3-server.go:1255` and enforced in the single accept-loop goroutine (`:1258-1270`), default `64` (`:1004-1009`). Prune: `util/util.go:356-362` adds `SyncMap.Delete`; called at `cmd/ssh3-server.go:1353` in the session goroutine's teardown defer. SFTP children: per-user budget `cmd/sftp_subsystem.go:52-57,99-103`, default 16 (`cmd/ssh3-server.go:1010-1015`), plus in-process serving when unprivileged (`:95-97`, `:182-203`). **But the prune does not cover the budget-refusal path** (`Insert` at `:1329` precedes admission at `:1335`) — see **P3-01**; and the per-user sftp cap is skipped in the in-process branch — see **P3-04**. |
| **S2-03** | Channel-type role inversion (`forwarded-*` accepted from clients; `direct-*` unrecognised by the server) | **FIXED** (the fix is right; the pass-2 description of the old behaviour was partly wrong) | Server now refuses client-opened `forwarded-tcp`/`forwarded-udp` with a stream error before any dispatch: `server.go:171-182`. Client now refuses server-opened `direct-tcp`/`direct-udp`: `conversation.go:316-322`. Correction to pass 2: `server.go:202,210` **did** already map `direct-udp`/`direct-tcp` to the forwarding impls at `ff5ef77`, so the server was not blind to them, and a client-opened `forwarded-*` fell through to the *session* branch rather than being dialled (the dial path is only reachable for the `direct-*` types). The role inversion was therefore a dead-session-slot issue, not a dial-vs-answer confusion. The remediation is correct in both directions. |
| **S2-04** | No `PermitListen` analog for reverse-forward binds | **FIXED** | `permitListen` policy var `cmd/forward_policy.go:40-44`, flag/env `cmd/ssh3-server.go:1002-1005`, single gate `checkListenTarget` `cmd/forward_policy.go:127-137`, applied to **both** protocols (`listenKind` from `request.Protocol`) on the **post-GatewayPorts** address actually bound, `cmd/reverse_forward_server.go:225-236`. Default empty spec ⇒ unrestricted (documented in the flag help). The denial path releases the bind-budget slot taken earlier in the same function, so accounting stays balanced (`:232` vs the acquire-failure release at `:217`); the code comment claiming the gate runs *before* the budget is cosmetic only. |
| **S2-05** | `lexical` jail keeps the F-04 exposure; in-process `pkg/sftp` unguarded | **FIXED** (panic containment) / **PARTIALLY FIXED** (jail) | `PanicGuard` now wraps `serveSFTPSubsystem` (`cmd/sftp_subsystem.go:89`) and both pump goroutines (`:158,165`), so a `pkg/sftp` panic kills the channel, not the server. The lexical fallback still exists by design (`cmd/sftp_subsystem.go:95`) and is now also what an **unprivileged** server uses, in-process, with `newSFTPHandlers(user.Dir, …)` (`:183`) as a lexical root — the same confinement the old child got via `-sftp-root`, so not a regression, but the `chroot` mode silently degrades to lexical whenever `euid != 0` (`:95-97`, `:117-119`). |
| **S2-06** | No QUIC timeouts / connection cap / stream caps | **FIXED** | `quic.Config` now sets `MaxIdleTimeout`, `HandshakeIdleTimeout`, `MaxIncomingStreams`, `MaxIncomingUniStreams` explicitly (`cmd/ssh3-server.go:1222-1230`) from flags/env with quic-go-equal defaults (`:1016-1030`: idle 30 s, handshake 5 s, 100 streams). Connection cap `-max-connections` (default `0` = unlimited) enforced in the accept loop `cmd/ssh3-server.go:1493-1502`. |
| **S2-07** | Varint encoder panics latent | **FIXED-SHALLOW (unchanged class, now pinned by tests)** | The encoders themselves are untouched; `util/wire_test.go` gains a roundtrip edge test and `FuzzVarIntAppendReadRoundtrip` (last ~30 lines of the file) which *skips* values > 2^62-1 rather than asserting non-panicking behaviour. The latent-panic class therefore survives exactly as pass 2 described; the tests document the caller invariant instead of removing the landmine. |
| **F-05** | Forward-target policy (SSRF/pivot) | **PARTIALLY FIXED (unchanged)** | `-permit-open` still defaults to unrestricted and still governs *dials* only; the new `-permit-listen` closes the *bind* half. Two policy mechanisms now exist, both opt-in. |
| **F-09** | Varint panics latent | **STILL PRESENT (latent)** | see S2-07. No new arithmetic-derived call site was introduced by the remediation (the clamp uses `util.MinUint64`). |
| **F-12** | Client `Match exec` runs a shell command while parsing `~/.ssh/config` | **STILL PRESENT** | client-side, untouched by this series; not re-walked. |
| **F-13** | Host-key pin comparison not constant-time | **STILL PRESENT (CONFIRMED as before)** | untouched; the compared value is a public certificate. |

---

## 3. Regression hunt on the fixes

### 3.1 `maxPacketSize` clamp (S2-01) — both paths, interop, semantics

* **Both inbound paths?** Yes, and they are the only two. Server: `server.go:176-182` (inside `handleChannelStream`, before `ChannelInfo`/`NewChannel` at `:194-206`). Client: `conversation.go:294` (inside `handleIncomingChannelStream`, before `NewChannel` at `:313`). The only remaining inbound channel paths funnel through these two functions (`conversation.channelsAcceptQueue.Add`, `Server.handleChannelStream`), including muxed conversations.
* **Ordering is correct:** the clamp runs before the buffers are allocated; the buffers (`cmd/ssh3-server.go:249,357,830`, `cmd/dynamic_forward_server.go:388`) are created inside handlers that read `channel.MaxPacketSize()` after admission, so they can no longer see the raw peer number.
* **Interop with older peers: no wire change.** The clamp is purely local — no new message, no version check, and the channel-open confirmation still announces the local value (`channel.go:360-362`; client accept path `conversation.go:480`). Every in-repo peer advertises 30000 (`cmd/ssh3-server.go:1245`, `client/client.go:485,533`, `internal/interop/go_server/main.go:645,750`), i.e. `min` is the identity for them, so intra-project interop is unchanged. A third-party peer advertising more than the local value is silently lowered, which the spec-correct reading permits (the confirmation already told it the receiver's value).
* **Semantics check — is a smaller read buffer lossy?** `channelImpl.MaxPacketSize()` is used for three things: the read chunk size, the `sync.Pool` buffer size in the session pump, and the *outbound* chunk limit in `WriteData` (`channel.go:339`). A lower read buffer does **not** truncate: `ChannelReadWriteCloser.Read` drains a message into `c.pending` and hands out slices across calls (`channel_rwc.go:25-33`), so stream data survives a buffer smaller than the message. No data-loss regression found on the byte-stream paths (TCP forwarding, session stdio, sftp in-process — the latter uses the same read-write closer).
* **Interop asymmetry worth noting (not a defect of this fix):** `channelImpl.NextMessage` discards `ChannelOpenConfirmationMessage` after setting `confirmReceived` and never adopts the confirmed `MaxPacketSize` (`channel.go:294-305`). A peer therefore keeps chunking its writes at the value *it* advertised; if that value is larger than the receiver's clamped buffer the messages simply arrive larger than the read chunk and are split by the read-write closer. Correct but implicit — the spec/comment would be worth stating.
* **Peer value 0 or 1 is preserved by design** (the new unit test asserts `clamp(0, 30000) == 0`, `max_packet_size_test.go:13-20`) → see **P3-02**.

### 3.2 Channel / subsystem cap (S2-02) — where counted, races, leaks

* **Where counted:** in the *accept loop* of the conversation handler, not in the handlers, via `spawnChannel` (`cmd/ssh3-server.go:1258-1270`). Admission (`tryAcquire`) runs in the loop goroutine only, i.e. serialized, so **concurrent opens cannot race past the cap**; the count is incremented before the goroutine starts and decremented by `defer channels.release()` inside that goroutine.
* **Scope:** per *conversation* (`channels := newBudget(...)` inside the conversation handler closure, `:1255`), and per *user* for sftp children (`sftpChildrenBudgets`, `cmd/sftp_subsystem.go:52-57`). There is **no** cap across a user's conversations: a mux control master or simply many CONNECTs multiplies the per-conversation budget by the number of conversations (`-max-connections` is the only cross-conversation bound and defaults to unlimited). That is the same multiplication pass 2 flagged one level up; it is now bounded per conversation but not per user/connection.
* **Leak on abnormal close:** none on the handler side — `release` is a deferred call in the same goroutine as `run()`, so it runs on panic (verified: inside the goroutine the registered defters are `PanicGuard` then `release`; LIFO runs `release` first, then the guard recovers) and it runs *after* the session's own teardown defters (`:1345-1360`) because those are nested inside `run()`. The slot is held for up to the `DrainAndClose(3 s)` window, which is harmless. The refusal path takes no slot (it closes the channel and returns), so the *budget* cannot leak.
* **`runningSessions` prune (the mandated use-after-prune question):** clean, with one gap. `Delete` runs in the session goroutine's teardown defer (`:1353`) after `channel.Close()` and before the multiplexed early-return, so a muxed master also prunes. Every lookup that could race it — `:502` (`newPtyReq`), `:549` (`newCommand`), `:705`, `:731`, `:795`, `:1371`, `:1432` — is `runningSessions.Get(channel)` with an explicit `ok` check and an error return, and the map value is only dereferenced after `ok`; no nil dereference or use-after-prune is possible. The key is the channel *object* (not the stream id), so two connections can never collide on an equal id. The gap is the **refusal path**: `Insert` at `:1329` happens before admission at `:1335`, so a budget-refused session channel is inserted and never deleted (`Delete` lives only in the spawned goroutine) — **P3-01**.

### 3.3 SFTP (S2-05) — child re-exec, drop ordering, fd leakage, lexical fallback

* `cmd/internal_sftp.go` is untouched by this series (confirmed by `git show --stat 73aecac`); the child re-exec, `Chdir → Chroot → Chdir("/") → Setgroups → Setgid → Setuid` ordering and the fail-closed root check verified in pass 2 therefore still hold verbatim at `8725d65` and were not re-walked.
* The remediation changed **which** path runs, not the confinement of the child: `serveSFTPChrootChild` (`cmd/sftp_subsystem.go:110-180`) still passes `-sftp-chroot/-sftp-uid/-sftp-gid` only when `euid == 0` and `-sftp-root user.Dir` otherwise (`:117-125`), with a sanitized env and two pipes. The new in-process branch (`:95-97` → `:182-203`) uses `newSFTPHandlers(user.Dir, user.Uid, user.Gid)` as a lexical root, i.e. the same "prefix under `user.Dir`" confinement the unprivileged child had. No uid/gid drop is performed in the in-process branch (there is nothing to drop — the process is already the server's identity); the operator-visible consequence is that `-sftp-jail chroot` is a no-op for an unprivileged server (documented here, not in the flag help).
* **fd leakage:** the in-process branch opens no fds of its own; the child path is unchanged and pass-2's fd accounting (pipes closed by the parent after `cmd.Wait`) still applies. No new fd-carrying code in the remediation.
* **Lexical fallback:** still present, now reachable two ways (explicit `-sftp-jail lexical`, or implicitly because `euid != 0`). Since the unprivileged child already had the same lexical view, this is a behaviour *documentation* gap rather than a new exposure.

---

## 4. New findings on changed code

| ID | Severity | Component | Evidence at `8725d65` | Impact / exploit conditions |
|---|---|---|---|---|
| **P3-01** | **Low** (post-auth) | `runningSessions` entry leaks on the budget-refusal path — the S2-02 prune does not cover it | `cmd/ssh3-server.go:1329` (`runningSessions.Insert`) precedes admission at `:1335`; the only `Delete` is at `:1353`, inside the goroutine that `spawnChannel` may refuse to start | An authenticated peer that keeps the conversation's channel budget exhausted (≥64 long-lived channels: sftp, `-D` control, sessions) and then opens more **session** channels causes one permanently retained `runningSessions` entry (plus the referenced channel object) per refused channel, unbounded for the process lifetime — the exact growth S2-02 set out to stop. Requires a valid account and channel churn; each iteration is cheap because the refused stream is closed at once. Fix: insert after admission, or `Delete` on the refusal path. |
| **P3-02** | **Info / Low** (post-auth, self-inflicted) | The clamp has no floor; a peer advertising `0`/tiny `maxPacketSize` reaches a uint64 underflow in the writer | Clamp is `min(peer, local)` only (`channel.go:163-170`); the new test enshrines `{0 → 0}`, `{1 → 1}` (`max_packet_size_test.go:13-20`). `WriteData` computes `c.ChannelInfo.MaxPacketSize - emptyMsgLen` in `uint64` (`channel.go:339`) | With `maxPacketSize < ` the data-frame overhead, the subtraction wraps to ~2^64: the endpoint then sends the whole caller buffer as one oversized message to a peer that claimed it can accept almost nothing, and the per-channel read buffer is 0/1 byte. Reachable before the fix too (the value was passed through verbatim), so this is *unfixed*, not *introduced*: the remediation chose to preserve peer-smaller values rather than floor them at a sane minimum. Suggest `max(peer, MIN_SANE_PACKET_SIZE)` or clamping *up* to the local value in the underflow case. |
| **P3-03** | **Low** | The channel-role check is a negative list, not an allow-list | Refusals at `server.go:171-182` and `conversation.go:316-322` name the four known role-violating types only; every other unknown string still reaches the session `default:` branch (`cmd/ssh3-server.go:1330-1340`) | An authenticated client can still open an arbitrary channel-type string and occupy a session slot (and now also the channel budget) for a channel the server never intended to accept. This is what S2-03 recommended against ("accept only the client-role names"); the fix closed the two named cases, not the class. Low: no privilege change (the session path validates its own requests), and the channel budget bounds the count. |
| **P3-04** | **Info** (post-auth, operator config) | `-max-sftp-sessions-per-user` is a no-op whenever the server serves sftp in-process | `cmd/sftp_subsystem.go:95-97` returns into `serveSFTPInProcess` **before** the budget check at `:99-103` | On any unprivileged server (and in explicit `lexical` mode) the only sftp concurrency bound is the per-conversation channel budget, so the documented per-user knob silently does nothing. Not a resource regression versus pass 2 (the in-process mode is cheaper than a process per channel), but the flag help overstates the guarantee. |
| **P3-05** | **Info** | Signal/window requests racing a pruned session now get a hard error | `cmd/ssh3-server.go:502,549` return `"internal error: cannot find session for current channel"` when the lookup misses; the prune at `:1353` makes a late `SIGWINCH`/signal from the client miss | Correct enough (the session really is over) but it turns the last signal of a fast-exiting command into a visible protocol error. Cosmetic; mentioning it so the pass-2 "prune" question is answered for signal delivery explicitly. |
| **P3-06** | **Info** | `c4aea26` (sftp client pipelining) is a behavioural change in the *client* data path, not covered by this pass | `cmd/sftp_client.go` +262/-30, `cmd/sftp_client_test.go` +153; no security review of it was possible in this pass | Client-side only, so the exposure is the operator's own client; flagged as unreviewed rather than cleared (see Coverage). |

**Positive re-verification (things the remediation got right and the sweep confirmed):** the refusal branches use stream errors and return *before* any queue/goroutine/allocation work (`server.go:176-182`); `spawnChannel` gives every handler family the same PanicGuard, extending the pass-2 guard placement to the four `go`-spawned handlers the old code left unguarded; `budget.tryAcquire`/`release` are mutex-protected and `release` clamps at zero, so a mistimed release cannot manufacture extra slots; the `maxConnections` check runs under `connsMu` before the map insert (`cmd/ssh3-server.go:1494-1502`), so the count cannot race past the limit.

---

## 5. Pass-2 loose end, closed: the CLI channel-type string for `-L`

**Answer: `direct-tcp` (TCP) and `direct-udp` (UDP), and the server accepts exactly those names for the dial direction.**

* Client side: the CLI forwarding path opens `c.OpenTCPForwardingChannel(30000, 10, …)` (`client/client.go:533`) / `c.OpenUDPForwardingChannel(30000, 10, …)` (`:485`); those constructors hard-code the channel-type strings `"direct-tcp"` (`conversation.go:428-436`) and `"direct-udp"` (`conversation.go:413-421`). The `-R` counterpart goes through `openForwardedChannel` → `"forwarded-tcp"`/`"forwarded-udp"` (`conversation.go:447-469`).
* Server side: the inbound switch maps exactly `"direct-udp"` → `UDPForwardingChannelImpl` and `"direct-tcp"` → `TCPForwardingChannelImpl` (`server.go:202-213`), which is what the session loop dispatches to `handleUDPForwardingChannel`/`handleTCPForwardingChannel` (`cmd/ssh3-server.go:1280-1290`) under `checkForwardTarget` (permit-open). This mapping existed before the remediation, so the pass-2 statement that the server "does not recognise `direct-tcp`/`direct-udp`" was wrong — the loose end is resolved *against* that description.
* Does the server accept only the names it should? It now refuses the two server-role names from a client (`forwarded-tcp`/`forwarded-udp`) and the client refuses the two client-role names from a server, which makes the role table direction-consistent for the four names that matter. It is still not a positive allow-list: any other string reaches the session branch (**P3-03**). Documenting the table (direction → permitted types) in the spec/README — pass 2's recommendation (c) — is still outstanding.

---

## 6. Dynamic probes

All probes were run locally with a recovered `go1.26.0` toolchain against the audited checkout, vendor mode, read-only, no third-party system contacted, no live attack.

| Probe | Result |
|---|---|
| `go vet ./util/ ./message/` | see the run log below |
| `go test ./util/ ./message/` | see below |
| `go test ./ -fuzz FuzzParseSSHString -fuzztime 30s` | see below |
| `go test ./ ./cmd/` (the packages whose tests the remediation added: `max_packet_size_test.go`, `cmd/channel_budget_test.go`, `cmd/forward_policy_test.go`) | see below |
| Cheap probe for the new caps/limits | static only: the semaphore is a plain mutex-guarded counter (no `sync/atomic`, no lock-free path); the new unit tests `cmd/channel_budget_test.go` and `cmd/forward_policy_test.go` cover the arithmetic and the permit-listen gate. No dynamic concurrency probe (e.g. racing 200 channel opens against the 64 cap) was run — stated as not covered. |

**Probe results (run log, abridged):**

```
go version go1.26.0 linux/amd64
=== go vet ./util/ ./message/ ===
vet_exit=0
=== go test ./util/ ./message/ ===
ok      github.com/francoismichel/ssh3/util     0.052s
ok      github.com/francoismichel/ssh3/message  0.413s
test_exit=0
```

`go vet` on the two packages touched by the remediation's parsing changes is **clean**, and both package test suites (including the new varint roundtrip/fuzz-seed tests added for S2-07) **pass**. The 30 s `FuzzParseSSHString` smoke and the `go test ./ ./cmd/` run were started after those, on a cold `go1.26.0` build cache; the cache was still warming when this report was written, so **their results are not covered by this pass** — no failure was observed, but a fuzz/build run that has not finished is not evidence, and it is not reported as one. The two test files the remediation added for the new caps (`cmd/channel_budget_test.go`, `cmd/forward_policy_test.go`) were read statically rather than executed.


Honest coverage statement: the probes that ran are **unit/static only**. There was **no** end-to-end run against a live server, **no** adversarial channel/channel-budget load, and **no** test of the clamp against a peer that advertises a non-30000 value (the new unit test exercises the pure function, not a negotiated channel).

---

## 7. Rust `crates/ssh3-server` (pass-1 leftover) — **NOT COVERED**

Unchanged in this pass, as in pass 2: the Rust workspace's `unsafe` blocks and the `crypt(3)` FFI were not triaged. The `Cargo.lock` advisory bump noted in pass 1 (F-10, `rustls 0.23.45`) was not re-checked against a current advisory feed either. This remains the oldest open item in the engagement and needs its own budget slot.

---

## 8. Coverage and limitations

**Covered in this pass**
- Every hunk of `73aecac` (the only code-bearing commit since the pass-2 baseline), read against its surrounding code at `8725d65`.
- The two inbound channel paths (`server.go:130-215`, `conversation.go:285-345`), the channel budget and `spawnChannel` (`cmd/ssh3-server.go:1250-1360`), the session-map prune and all seven lookup sites, the sftp spawn/in-process branches (`cmd/sftp_subsystem.go:80-205`), the reverse-forward `-permit-listen` gate (`cmd/reverse_forward_server.go:185-300`), the quic config and connection cap (`cmd/ssh3-server.go:1210-1235`, `1490-1505`), the new flag defaults and env parsing (`:1000-1035`), the new tests.
- The CLI `-L`/`-D` channel-type question (loose end) end-to-end through the client constructors and the server's inbound table.

**Not covered / limits**
- **No end-to-end or adversarial dynamic test.** The fixes were verified by reading code and running unit tests; the memory-pressure claim behind S2-01 is now structurally bounded (peer ≤ local ≤ 30000), but the effective ceiling per connection was not measured. Likewise the channel-budget cap was not exercised under concurrent opens.
- `c4aea26` (sftp client pipelining, ~260 changed lines in `cmd/sftp_client.go`) received **no security review** — it is client-side and outside the remediation, but it *is* changed code, so it is flagged rather than cleared.
- `cmd/internal_sftp.go`, `client/client.go`, `cmd/dynamic_forward_server.go`, `cmd/dynamic_forward.go`, `server_auth/`, the `vendor/h3` patch and the Windows-specific files were **not re-walked** (unchanged since pass 2, whose findings are carried forward by reference). `internal/interop/` was used only as a reference for what peers advertise.
- The Rust crates and `crypt(3)` FFI: not covered (see §7).
- The per-conversation-channel-budget × conversations multiplication (no per-user/connection channel cap, `-max-connections` unlimited by default) is **analysed but not exploited**; treat it as a residual amplification path rather than a closed finding.
- Behaviour of a peer that ignores the confirmation and keeps chunking at its own larger `MaxPacketSize` was reasoned from the code but **not** tested against such a peer — no third-party client was available.

*Report-only: no code was changed anywhere. Every recommendation above is a proposal.*
