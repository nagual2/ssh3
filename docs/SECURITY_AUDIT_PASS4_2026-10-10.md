# Security audit — pass 4 (fix verification)

- **Audited revision:** `d9ea092` (`origin/main`, "Merge pull request #8 from nagual2/fix/goreleaser-package-main")
- **Baseline:** `8725d65` (pass-3 audited revision, v0.1.28)
- **Date:** 2026-10-10 (UTC)
- **Scope:** fix verification for the pass-3 findings (P3-01…P3-06) plus the pass-2 leftovers the pass-3 report carried forward (S2-07/F-09, F-05, F-12, F-13); regression hunt on the security-fix commit itself; new-findings sweep restricted to code changed since `8725d65`.
- **Report-only.** No code, test or configuration file was modified by this pass.
- Prior reports: pass 1 `docs/SECURITY_AUDIT_2026-10-06.md` (merged), pass 2 `docs/SECURITY_AUDIT_SERVER_PASS2_2026-10-07.md`, pass 3 `docs/SECURITY_AUDIT_PASS3_2026-10-09.md`.

Method: severity / impact / exploit conditions (pre-auth vs post-auth) / `file:line` at the audited HEAD; regression hunt before new findings; the Coverage and Limitations sections at the end state exactly what was and was not verified.

---

## 1. Change set `8725d65..d9ea092` (15 commits) and what each claims

| Commit | Claim | Security relevance |
|---|---|---|
| `a768ca7` | pass-3 audit skeleton | docs only |
| `b76a2e8` | pass-3 audit body | docs only |
| `55eb006` | merge PR #4 (pass-3 docs) | none |
| **`14032cd`** | **`fix(security): close the pass-3 audit findings (P3-01..P3-04)`** | **the remediation under audit**; `channel.go`, `conversation.go`, `server.go`, `cmd/ssh3-server.go`, `cmd/sftp_subsystem.go` + `channel_types_test.go`, `max_packet_size_test.go`, `cmd/sftp_budget_test.go` |
| `7cc3468` | release bump 0.1.29 | none |
| `d52a6c3` | `feat(client): configurable Term via -o, ssh_config, env and a 256-color default` | client-side PTY option; reviewed at a bounded level (§6) |
| `f975371` | `feat(winres): embed icon + version info into the Windows client` | adds committed **binary** artifacts (`cmd/ssh3/rsrc_windows_amd64.syso`, `icon.png`) (§6, P4-05) |
| `4837158` | merge PR #5 | none |
| `a47cc64` | `fix(sftp): --continue skips by size+mtime, not size alone` | client resume decision + **new server-side SETSTAT timestamp handler** in the sftp subsystem; reviewed (§6, P4-06) |
| `3922eee` | release bump 0.1.30 | none |
| `d206c36` | merge PR #6 | none |
| `6bbe89c` | regenerate `rsrc_windows_amd64.syso` for 0.1.30 | binary churn, unreviewable diff (§6) |
| `c2b1a95` | merge PR #7 | none |
| `965d739` | `fix(release): build the client from the package so the .syso resources link in` | `.goreleaser.yaml` one-liner |
| `d9ea092` | merge PR #8 | none |

Behavioural surface for this pass is therefore `14032cd` (the fixes), `a47cc64` (new sftp write path + resume semantics), `d52a6c3` (client PTY/Term), and the release/binary commits. `c4aea26` (pass-3's P3-06 pipelining feature) is still in the tree and still not line-by-line reviewed; `a47cc64` touches the same client file and is reviewed here (§6).

---

## 2. Finding status at `d9ea092`

Severity labels are the pass-3 labels, re-judged at this HEAD.

| ID | Pass-3 claim | Status | Evidence at `d9ea092` |
|---|---|---|---|
| **P3-01** | Budget-refused session channel leaks a retained `runningSessions` entry (Insert precedes admission, Delete only inside the spawned goroutine) | **FIXED** (one residual registry of the same class remains — P4-02) | `spawnChannel` now returns `bool` (`cmd/ssh3-server.go:1261-1275`), returns `false` after `CancelRead`+`Close` on refusal (`:1262-1268`), and the session branch undoes the pre-admission registration: `if !spawnChannel(...) { runningSessions.Delete(channel) }` (`:1339`, `:1453-1459`). Insert is still before admission (`:1333`) but every refusal path now prunes. |
| **P3-02** | Clamp has no floor → `uint64` underflow in `WriteData` (`MaxPacketSize - emptyMsgLen`) | **FIXED** (floor is one-sided; see P4-04) | `minPeerMaxPacketSize = 4096` (`channel.go:169`); `clampPeerMaxPacketSize` raises `peer` to the floor before `util.MinUint64(peer, local)` (`channel.go:178-183`); applied on both inbound paths before any buffer sizing: server `server.go:175`, client `conversation.go:294`. `WriteData` unchanged (`channel.go:385`), now unreachable with `MaxPacketSize < emptyMsgLen` for every configuration in the tree (§4). |
| **P3-03** | Channel-role check is a negative list; unknown type strings still become sessions | **FIXED** | Positive allow-lists `serverAcceptsChannelType` (`channel.go:198-206`) and `clientAcceptsChannelType` (`channel.go:210-218`), gated before any allocation: server `server.go:158-164`, client `conversation.go:295-304`. Unknown strings are now cancelled with a stream error and never reach the session branch. Pinned by `channel_types_test.go:10` / `:41`. |
| **P3-04** | `-max-sftp-sessions-per-user` is a no-op in the in-process path | **FIXED** | The per-user budget is acquired before the mode branch: `cmd/sftp_subsystem.go:95-99`, then `sftpJailMode == sftpJailLexical \|\| os.Geteuid() != 0 → serveSFTPInProcess` (`:104-107`), else `serveSFTPChrootChild` (`:108`). Regression tests: `cmd/sftp_budget_test.go:66` (refusal while in-process) and `:93` (slot held during serving, released after). |
| **P3-05** | Late signal/window request against a pruned session surfaces a protocol error | **NOT FIXED** (unchanged, by design) | Untouched by `14032cd`. `cmd/ssh3-server.go:502`, `:549`, `:705`, `:731`, `:795` still return an error when `runningSessions.Get` misses. All five lookups check `ok` before dereferencing, so this is a cosmetic path, not a memory-safety issue. |
| **P3-06** | `c4aea26` (sftp client pipelining) unreviewed | **PARTIALLY ADDRESSED** | `c4aea26` itself is still unreviewed line-by-line; the same file was reworked by `a47cc64`, which was reviewed this pass (§6). Client-side only (exposure is the operator's own client). |
| **S2-07 / F-09** | Varint landmines latent, pinned by tests instead of removed | **NOT FIXED** (unchanged, latent) | Unchanged by this change set; the clamping added by `14032cd` uses `util.MinUint64` and introduces no new arithmetic-derived varint call site. |
| **F-05** | Forward-target policy (SSRF/pivot) opt-in only | **PARTIALLY FIXED** (unchanged) | `-permit-open` still defaults to unrestricted for dials; `-permit-listen` (added before this change set) closes the bind half. Not touched by `14032cd`. |
| **F-12** | Client `Match exec` runs a shell command while parsing `~/.ssh/config` | **NOT FIXED** (unchanged) | Untouched; client-side, not re-walked this pass. |
| **F-13** | Host-key pin comparison not constant-time | **NOT FIXED** (unchanged) | Untouched; the compared value is a public certificate, so the practical impact remains nil. |

---

## 3. Regression hunt on the P3-01 fix (deepest attention)

**3.1 The refusal path no longer leaks the session entry.** `cmd/ssh3-server.go:1333` still inserts before admission, but the fix (a) makes `spawnChannel` return `false` when `channels.tryAcquire()` fails (`:1261-1268`) and (b) deletes the entry on the caller side when the spawn was refused (`:1453-1459`). Verified by reading the branch that owns the insert: the `if !spawnChannel(...)` block is the *same* branch that inserted, so no path inserts without a matching delete.

**3.2 Every `spawnChannel` call site checked** (`cmd/ssh3-server.go`): `:1286` (direct-udp), `:1291` (direct-tcp), `:1299` (sftp), `:1309` (reverse-forward), `:1318` (dynamic-forward), `:1327` (dynamic-forward-tcp) all discard the return value, and none of them registers anything before admission — the accept loop only logs before spawning, and each handler's own state (`getActiveDynamicForwardState` at `:1328`, the reverse-forward listener state) is created *inside* the goroutine, so a refusal starts no work at all. Only the session branch (`:1333`/`:1339`) registers before admission, and it is the only one that needed the undo — and has it.

**3.3 The budget slot cannot leak its own slot.** `tryAcquire` is called once, before the goroutine (`:1262`); on success the goroutine registers `defer util.PanicGuard(...)` first and `defer channels.release()` second (`:1270-1271`), so at unwinding the LIFO order runs `release` **before** the guard's `recover` — the slot is returned on a panic in `run()` as well as on normal return. The refusal path never acquires (it returns from `tryAcquire` false), so there is no release/acquire imbalance and no double release. `budget.release` additionally clamps at zero (`cmd/channel_budget.go:42-51`) under the same mutex as `tryAcquire`, so even a hypothetical extra release cannot manufacture slots.

**3.4 Use-after-Delete / mid-command lookups.** `runningSessions` is a `util.SyncMap` (`cmd/ssh3-server.go:124`) keyed by the channel *object*, so all operations are mutex-protected and two connections/streams cannot collide. All seven lookups (`:502` `newPtyReq`, `:549` `newCommand`, `:705` `newWindowChangeReq`, `:731` `newSignalReq`, `:795` `newDataReq`, plus the in-loop `:1375`/`:1436`) check `ok` before touching the value, and every one of them runs in the session goroutine (no `go newPtyReq`/`go newSignalReq`-style call exists anywhere in `cmd/`), i.e. the same goroutine that later deletes. The only cross-goroutine exposure is the *channel object* (handlers spawned inside `run()`), which holds a reference, not a map lookup. **No use-after-Delete, no nil dereference, no data race** on this map. The refusal-path `Delete` (`:1458`) runs in the accept-loop goroutine for a channel that never got a session goroutine, so it cannot race a live session.

**3.5 Residual of P3-01 — the second registry is still unpruned (P4-02, §6).** `AcceptChannel` registers the accepted channel in `channelsManager` (`conversation.go:482`) *before* returning it to the accept loop, so a channel the budget then refuses is registered, closed by the refusal path (`cmd/ssh3-server.go:1265-1266`) and never removed. The prune the fix added covers `runningSessions` only.

**3.6 No regression test for the P3-01 fix.** `14032cd` added tests for P3-02 (`max_packet_size_test.go`), P3-03 (`channel_types_test.go`) and P3-04 (`cmd/sftp_budget_test.go`, 122 lines), but nothing exercises the refusal path or `runningSessions` (`grep runningSessions *_test.go` → no match). The fix is correct by inspection; the guarantee is unprotected against regression (P4-03).

---

## 4. Regression hunt on the P3-02 fix

**4.1 The floor is present and precedes buffer sizing.** `channel.go:169` (`minPeerMaxPacketSize = 4096`), `channel.go:178-183`: `peer` is raised to the floor, then `util.MinUint64(peer, local)`. Both inbound paths clamp *before* the value is stored in `ChannelInfo` and before any handler allocates: server `server.go:175` (gate/ahead of `ChannelInfo` at `:178-184`), client `conversation.go:294` (ahead of `NewChannel` at `:323`). Read buffers (`cmd/ssh3-server.go:249,357,830`, `cmd/dynamic_forward_server.go:388`, `client/client.go:129,204`, `client/session_pump.go:91`) can therefore only see the clamped value.

**4.2 Re-derivation of the underflow guard.** `WriteData` chunks at `c.ChannelInfo.MaxPacketSize - uint64(emptyMsgLen)` (`channel.go:385`), where `emptyMsgLen = (&DataOrExtendedDataMessage{...empty}).Length()` (`:380-384`) — the frame's own header, of the order of 2 bytes (the test asserts the same: "below the 2-byte empty data frame", `max_packet_size_test.go:17`). The subtraction is safe iff `MaxPacketSize > emptyMsgLen`. With the floor, the clamp result is `min(max(peer, 4096), local)`, so it is `≥ 4096` **provided `local ≥ 4096`**. Every local advertisement in the tree is the 30000 constant: server `cmd/ssh3-server.go:1244` → `server_auth/auth.go:82` and `server.go:54-58`; client `client/client.go:323`, and every channel opener passes 30000 explicitly (`client/session.go:50`, `client/reverse_forward.go:124`, `cmd/sftp_client.go:134`, `cmd/subsystem.go:35,83`, `cmd/dynamic_forward.go:331,483`, `cmd/reverse_forward_server.go:361,401`, `cmd/ssh3-server.go:822,910`). No flag or config lowers it (no `-max-packet-size` exists). Hence the underflow is **not reachable at this HEAD** from any peer-controlled or configuration-controlled value: the peer can press the negotiated size down to 4096 at worst, a ~2000× margin over `emptyMsgLen`.

**4.3 Sweep for the same `MinUint64`-subtraction pattern elsewhere.** `grep -rn "MinUint64\|MaxUint64\|- uint64("` over non-vendored, non-test Go sources yields exactly two sites: `channel.go:182` (the clamp itself) and `channel.go:385` (the writer). The datagram paths (`conversation.go:496-510`, `resources_manager.go`, `channel.go:429-444`), the forwarding handlers and the sftp code contain no unsigned subtraction of a peer/length value. `util.ReadVarInt` callers bound values by `MaxSSHStringLen`/`parseHeader` (`channel.go:228-238`) rather than by arithmetic. No new instance of the class was introduced.

**4.4 Residual (P4-04).** The floor is applied to the *peer* value only; `util.MinUint64(peer, local)` can still return `local < floor` because the local value is never floored. `max_packet_size_test.go:35-40` (`TestClampPeerMaxPacketSizeSmallLocal`) pins exactly that: `clamp(0, 2048) == 2048`. It is harmless today only because all local values are the 30000 constant; the invariant is an unwritten property of the call sites, not of the function. A future configurable local size below ~2 bytes (or below `emptyMsgLen`) re-opens the underflow, and `msgLen == 0` (local exactly equal to `emptyMsgLen`) would spin `WriteData`'s loop. Recommend flooring the local at construction (`NewChannel`/`NewServerConversation`) or rejecting `MaxPacketSize <= emptyMsgLen` there.

---

## 5. P3-04 and P3-03 verification

**P3-04 — `-max-sftp-sessions-per-user` in the in-process path: enforced.** `serveSFTPSubsystem` acquires and defers the release before choosing the jail mode (`cmd/sftp_subsystem.go:95-99`), so the lexical/explicit-lexical and unprivileged branches (`:104-107`) are now bounded by the same per-user budget as the chroot child (`:108`). Where counted: per authenticated username, in `userBudgets.budgetFor` → `budget` (`cmd/channel_budget.go:62-84`); `budgetFor` takes the map mutex, and `tryAcquire`/`release`/`current` are mutex-protected with `release` clamping at zero — no race window and no way to gain slots. The release is deferred *after* the guard registered at `:90`, so the slot is returned on panic as well. The budget is keyed by username; each distinct authenticated user adds one small map entry (`cmd/channel_budget.go:75-84`), bounded by real system accounts and released with the server process — noted, not a finding. Both behaviours (refusal, hold/release) have dedicated tests (`cmd/sftp_budget_test.go:66,93`), and the in-process serving path itself is still wrapped in the S2-05 `PanicGuard` (`cmd/sftp_subsystem.go:90`).

**P3-03 — allow-lists: present, and consistent with the dispatch layers.** `serverAcceptsChannelType` (`channel.go:198-206`) allows exactly `session`, `sftp`, `direct-tcp`, `direct-udp`, `reverse-forward`, `dynamic-forward`, `dynamic-forward-tcp`; the server accept loop (`cmd/ssh3-server.go:1283-1332`) dispatches exactly those families (type-switch to the forwarding impls, then explicit `sftp`/`reverse-forward`/`dynamic-forward`/`dynamic-forward-tcp` branches, `session` last). `clientAcceptsChannelType` (`channel.go:210-218`) allows `forwarded-tcp`, `forwarded-udp`, `agent-connection`; the client's `acceptLoop` (`client/reverse_forward.go:26-58`) dispatches exactly those three. The wire strings match the constants (`message/reverse_forward.go:19-21`, `message/dynamic_forward.go:19-20`), and the in-repo interop peer opens `agent-connection` server→client (`internal/interop/go_server/main.go:637`) and `session`/`sftp` client→server — all allowed. **No functional regression found** for any in-repo peer; the only newly refused inputs are the four role-inverted names (already refused by pass-3's negative list) and arbitrary unknown strings, which now die before allocation.

---

## 6. New findings on changed code (pass 4)

| ID | Severity | Component | Evidence at `d9ea092` | Impact / exploit conditions |
|---|---|---|---|---|
| **P4-01** | **Low** (post-auth) | Unbounded `danglingDgramQueues` growth from peer-chosen channel IDs — a datagram naming a channel that does not exist creates a map entry nothing ever removes | `Conversation.AddDatagram` (`conversation.go:496-510`) reads the channel ID from the datagram, and on a miss calls `channelsManager.addDanglingDatagramsQueue(channelID, …)` (`resources_manager.go:71-87`) then returns `util.ChannelNotFound`. Entries are dropped **only** inside `addChannel` (`resources_manager.go:59-62`), i.e. only if a channel with that exact ID is registered later. Callers accept any inner ID: server datagram loop `server.go:305-318` (validates only the *conversation* ID, `:302`), client loop `conversation.go:216-231`. `conversation.go` is a changed file in this change set. | An authenticated peer (post-CONNECT, no channel or session needed) that keeps one conversation open can send datagrams with distinct channel IDs and each one permanently retains a `DatagramsQueue` (a channel with a 64-slot buffer, `util/util.go:135-137`) plus the copied datagram, for the conversation's lifetime. Retention is ~1 KiB+ per datagram with no cap and no reaping, so it is the same "grow until the connection ends" class the S2-02/P3-01 work set out to bound. Requires valid credentials; rate-limited only by the peer's own send rate. Suggest reaping dangling queues on a bound/TTL or dropping datagrams for unknown channels after the conversation's channel set has settled. |
| **P4-02** | **Low** (post-auth) | `channelsManager.channels` is never pruned — the close listener is wired but never invoked, so every channel (and especially the newly-refused ones) is retained for the conversation's lifetime | `channelCloseListener`/`onChannelClose` are declared (`channel.go:61-62`), stored at construction (`channel.go:294,312`) and implemented (`resources_manager.go:102-104`), but **nothing calls them**: `grep -rn "onChannelClose\|removeChannel"` finds only the interface, the field assignment, the two methods and the definition of `removeChannel`; `channelImpl.Close()` (`channel.go:459-461`) only closes the send side. Registration happens in `AcceptChannel` (`conversation.go:478-483`) and in every opener (`:410,425,439,457`). | Every channel ever accepted or opened keeps an entry in the per-conversation map — the channel object plus its 64-slot datagram queue — until the conversation is collected. The **new** refusal paths add sources: a budget-refused session/sftp/forwarding channel is registered by `AcceptChannel` and then refused+closed by `cmd/ssh3-server.go:1262-1268` (only `runningSessions` is pruned at `:1458`); a client-side channel that passes the allow-list but fails `authorizeForwardedTarget` is closed unpruned (`client/reverse_forward.go:32,41,57`). Same registry-leak class as P3-01: the fix closed one of the two registries. Pre-existing (the listener was already dead before this change set), so it is *not introduced* by the fixes — but the refusal path is exactly the churn P3-01 was about, and the count is still unbounded over a conversation's life. |
| **P4-03** | Info | The P3-01 fix has no regression test | `14032cd` adds `channel_types_test.go`, `max_packet_size_test.go`, `cmd/sftp_budget_test.go`; no test references `runningSessions`, `spawnChannel` or a refused channel in `cmd/` | The corrected ordering (undo the insert when the spawn is refused) is verified only by reading; a future refactor of the accept loop can silently restore the leak. Recommend a test that exhausts `newBudget` and asserts `runningSessions` is empty/uncontended afterwards, mirroring `cmd/sftp_budget_test.go`'s stub-channel style. |
| **P4-04** | Info | The P3-02 floor bounds the peer value only, not the local one | `channel.go:178-183`; `max_packet_size_test.go:35-40` pins `clamp(0, 2048) == 2048` | Safe at this HEAD (every local value is 30000, §4.2), unsafe by construction: the `MaxPacketSize > emptyMsgLen` invariant lives in the call sites, not in the clamp or in `NewChannel`. Floor/validate the local value where it is constructed. |
| **P4-05** | Info | Committed opaque Windows binaries | `f975371` adds `cmd/ssh3/rsrc_windows_amd64.syso` (57 KB) and `cmd/ssh3/icon.png`, with a reviewable source (`cmd/ssh3/winres.json`, `cmd/ssh3/gen-syso.ps1`) alongside; `6bbe89c` regenerates the `.syso` for 0.1.30; `965d739` makes goreleaser build from the package so the blob links in | The generated `.syso` cannot be reviewed as code, and the two commits that touch it are pure binary diffs; provenance rests on `winres.json`/`gen-syso.ps1` plus the release pipeline. No evidence of tampering (the generator and its inputs are committed and the file is regenerated in-repo), but the reviewer of any future change to it has nothing to inspect. Acceptable for the Windows packaging goal; keep regenerations separate and small, as done here. |
| **P4-06** | Info (post-auth, client-side, requires a dishonest peer) | `a47cc64`'s resume decision and the new server SETSTAT path — reviewed and bounded this pass | Client: skip only when size **and** mtime match (`cmd/sftp_client.go:365-375,471-481`), mtime stamped after success (`:409-416,535+`), `Chtimes` failure non-fatal. Server: `Setstat` now handled (`cmd/sftp_subsystem.go:303-330`), honouring **timestamps only** (`attrs.Mtime`/`Atime`, else `ErrSSHFxOpUnsupported`), on a path that goes through the same `h.resolveJailed(request.Filepath)` as `mkdir`/`rename`/`remove`, via `os.Chtimes` | The change makes the skip decision *fail-safe*: equal size with a differing mtime re-transfers, so a source rewritten in place is no longer silently skipped. Residual trust: the mtime is still the peer's claim, so a malicious server that reports matching size+mtime for changed content can still make the client keep a stale local copy — but it could equally serve different bytes during a real transfer, so this is a continuation of the existing peer-trust boundary, not a new one. The server-side handler adds no capability beyond setting timestamps on a jail-resolved path; symlink handling is that of the pre-existing `resolveJailed`, unchanged by this commit (not re-walked). `d52a6c3`'s configurable `Term` is a client-side option the operator sets; it is forwarded in the PTY request as before (no privilege implication server-side). |

**Positive re-verification.** The remediation is directionally right in all four fixes: refusal happens before any allocation/goroutine/queue work (`server.go:158-164`, `conversation.go:295-304`), the session-branch undo is in the same branch as the insert, the floor sits ahead of every buffer allocation, the allow-lists match both dispatch layers, and the per-user sftp budget now covers both jail modes with a panic-safe release. `budget` accounting is mutex-protected and clamps at zero; `util.SyncMap` keeps the session map race-free; the full test suite (root, `cmd`, `client`) plus `go vet` and a 30 s fuzz run of the parser are green at this HEAD (§7).

---

## 7. Probes (executed at `d9ea092`)

| Probe | Result |
|---|---|
| `go vet ./util/ ./message/` | clean (no diagnostics), Go 1.26.0 linux/amd64, HEAD `d9ea092` |
| `go test ./util/ ./message/` | `ok` both packages |
| `go test -fuzz=FuzzParseSSHString -fuzztime=30s ./util/` | PASS, 818 492 executions (~27k/s, 2 workers), 8 new interesting inputs, no crasher written |
| `go test ./ ./cmd/ ./client/` | all `ok` (root 0.073 s, `cmd` 2.331 s, `client` 0.307 s) |
| Targeted new tests (`TestClampPeerMaxPacketSize`, `…SmallLocal`, `TestServerAcceptsChannelType`, `TestClientAcceptsChannelType`, `TestSFTPSubsystem*`, budget tests) | all PASS |
| Standalone re-derivation of `emptyMsgLen` (`/opt/probe_p4.go`) | **did not compile** (the probe used the wrong package qualifier for `DataOrExtendedDataMessage`/`SSHDataType`); `emptyMsgLen` is therefore quoted from the fix's own test comment (`max_packet_size_test.go:17`, "the 2-byte empty data frame") rather than independently measured — see Limitations. The margin argument in §4.2 does not depend on the exact value: any header length below 4096 keeps the guard closed, and the frame header is a handful of varint bytes |
| Cheap floor/cap probe | not run as a runtime probe; the floor/cap behaviour is covered by the committed unit tests above (pattern-matched, not attacked) |

No live attacks, no end-to-end server run, and no network traffic were performed in this pass. The datagram/registry findings (P4-01/P4-02) are established by code reading of the registration/removal paths, not by an observed memory measurement.

---

## 8. Coverage and limitations (honest bounds)

**Covered this pass.** The whole change set `8725d65..d9ea092` at hunk level; `cmd/ssh3-server.go` accept loop and session branch (lines ~1240-1460 read in full); `channel.go` (clamp, allow-list helpers, `NewChannel`, `NextMessage`, `WriteData`, channel close/datagram methods); `conversation.go` inbound classification, accept queue, datagram dispatch and the openers; `server.go` inbound channel path; `resources_manager.go` in full; `cmd/sftp_subsystem.go` (budget placement, jail-mode branch, the new `setstat`); `cmd/channel_budget.go` in full; the new/updated tests; the client accept loop; the channel-type string constants and their users across `client/`, `cmd/` and `internal/interop/`.

**Not covered.** (a) `c4aea26`'s pipelining internals remain unreviewed line-by-line (client-side; its file was touched and reviewed by this pass only for the `a47cc64` delta). (b) Files untouched by the change set were deliberately not re-walked — pass 1/2/3 coverage stands as written, including the lexical-jail resolution internals (`cmd/internal_sftp.go`, `resolveJailed`) and the varint encoder family. (c) `d52a6c3`'s Term plumbing was reviewed only at the "no privilege implication" level, not line-by-line. (d) The Rust workspace `crates/ssh3-server` (unsafe blocks, crypt(3) FFI), uncovered in all three earlier passes, **was skipped again** — the secondary priority did not fit this pass's ordering, and it is therefore *still* not covered (see below). (e) No runtime memory measurement of P4-01/P4-02 (no live server run); the findings rest on the absence of any removal path, verified by exhaustive grep for the two removal functions and their callers. (f) `emptyMsgLen` was not independently compiled/measured (probe compile error); it is taken from the repository's own assertion.

**Explicitly skipped, still uncovered:** Rust `crates/ssh3-server` unsafe/FFI triage (would need a `cargo`-side pass or a targeted reading of the `crypt(3)` FFI shim). It should be the first item of a pass 5 if it matters; a fourth consecutive pass leaving it uncovered means the Rust side has no audit coverage at all.

---

## 9. Recommendations, in priority order

1. **P4-01** — bound or reap `danglingDgramQueues` (cap per conversation, TTL, or drop after the channel set settles).
2. **P4-02** — actually invoke the close listener (`channelImpl.Close` → `onChannelClose` → `removeChannel`), or delete explicitly on the new refusal paths so both registries are pruned like `runningSessions`.
3. **P4-03** — regression test for the refusal-path prune (P3-01), in the style of `cmd/sftp_budget_test.go`.
4. **P4-04** — floor/validate the local `maxPacketSize` where channels are constructed, so the `MaxPacketSize > emptyMsgLen` invariant does not depend on call-site constants.
5. Docs: state the direction → permitted-channel-type table (carried over from pass 3, still outstanding) and the `-sftp-jail chroot` no-op for unprivileged servers.
6. Pass 5 should finally cover the Rust crates and the `crypt(3)` FFI.
