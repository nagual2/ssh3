# Security Audit — Pass 5 (fix verification, regression hunt, Rust server, distribution)

**Repository:** nagual2/ssh3-go
**Audit HEAD:** `e760a882ae8541bcf5748979728ab4d63c7b48b4` (origin/main)
**Previous pass baseline:** `d9ea092` (pass-4 audit, report merged as 28c9009)
**Date (UTC):** 2026-10-10
**Type:** report only — no code, configuration or workflow changes in this branch.

## Scope

Commits under audit, `d9ea092..e760a88`:

| Commit | Subject | Notes |
| --- | --- | --- |
| `dc1b8a4` | fix(security): close the pass-4 audit findings (P4-01..P4-04) | 7 files, +298/-17; full diff read |
| `f082c1a` | Merge PR #10 (`fix/pass4-findings`) | merge of the above |
| `60f5af5` | chore(release): bump software version to 0.1.31 | `version.go` only |
| `e760a88` | chore(winres): regenerate rsrc_windows_amd64.syso for 0.1.31 | **binary resource changed** (70882 → 57288 bytes) |

Distribution was updated as the owner said: there is a release-engineering change in scope
(the `.syso` regeneration) and a new release workflow/version bump chain. It was reviewed in
section 4 — the `.syso` is still a committed opaque binary, see P4-05.

## 1. Fix verification — status table

Line numbers are at `e760a88` (HEAD of this audit).

| ID | Sev | Claim | Status | Evidence at HEAD |
| --- | --- | --- | --- | --- |
| **P4-01** | Low (post-auth) | Dangling datagram queues bounded per conversation | **FIXED** (with a caveat, F-15) | `resources_manager.go:21` (`maxDanglingDatagramQueues = 256`), `:94-98` (cap enforced for brand-new IDs only, datagram dropped + `log.Warn` when full), `:87-101`; removal only on registration `:67-70` |
| **P4-02** | Low (post-auth) | `channelsManager.channels` pruned on close | **FIXED for every `Close()` path; PARTIAL overall** (CancelRead does not prune) | `channel.go:487-497` (listener invoked after `send.Close()`), `resources_manager.go:114-122` (`removeChannel`/`onChannelClose`), all 6 `NewChannel` call sites pass the manager: `conversation.go:323,409,422,437,455`, `server.go:196` |
| **P4-03** | Low | P3-01 insert/undo pairing pinned by a regression test | **PARTIAL — test does not exercise the production refusal path** | extraction `cmd/ssh3-server.go:126-145`, call site `:1354`; test `cmd/session_admission_test.go:36-57` injects its own `spawn` stub; production `spawnChannel` is a closure at `cmd/ssh3-server.go:1282-1296`, unreachable from a test |
| **P4-04** | Low | Local `maxPacketSize` advertisement floored | **FIXED** (no protocol-confirmation change) | `channel.go:193-198` (`clampLocalMaxPacketSize`), applied at `channel.go:313` before header (`:315-320`) and `ChannelInfo` (`:320`); `WriteData` fail-fast `channel.go:397-407`; tests `max_packet_size_test.go:47-52,56-78` |
| **P4-05** | Low (supply chain) | Committed opaque `.syso` binaries | **NOT FIXED — and the diff makes it worse for this release** | `git ls-files '*.syso'` → `cmd/ssh3/rsrc_windows_amd64.syso` still tracked; `e760a88` replaced its bytes by hand; no `winres`/`rsrc` reference anywhere in `.github/workflows/` or `Makefile` |
| **P4-06** | Info | `SETSTAT` (`a47cc64`) reviewed OK | **Unchanged / still OK** | `a47cc64` is not in `d9ea092..e760a88`; the pass-4 review stands, not re-walked |
| **P3-05** | Info | Signal/window request racing a pruned session gets a hard error | **STILL PRESENT (cosmetic, unchanged)** | unchanged lines between `d9ea092` and HEAD; `cmd/ssh3-server.go:502,549` per pass 3 |
| **S2-07 / F-09** | Low latent | Varint encoder panics latent | **UNCHANGED** | no varint code in the fix diff; the new clamps use `util.MinUint64` (no new arithmetic site) |
| **F-05** | Med (design) | Forward-target policy (SSRF/pivot) | **UNCHANGED (partial)** | untouched by `dc1b8a4`; `-permit-open` still unrestricted-by-default and governs dials only |
| **F-12** | Low (client) | Client `Match exec` runs a shell command while parsing `~/.ssh/config` | **UNCHANGED (not re-walked)** | client-side file untouched in this range |
| **F-13** | Info | Host-key pin comparison not constant-time | **UNCHANGED** | untouched; compared value is a public certificate |

## 2. Regression hunt on the P4 fixes

### 2.1 P4-01 — is the bound real, and what happens at the bound?

* **Where it is enforced:** `channelsManager.addDanglingDatagramsQueue` (`resources_manager.go:79-105`),
  under the manager mutex, *only when the ID has no queue yet* (`:87-98`). An existing queue is
  always extended (`:102-104`), so the cap cannot truncate the legitimate late-registration race.
* **Can peer behaviour still grow it?** Not without bound: at most 256 IDs × a fixed 64-slot
  queue per conversation (`danglingDatagramQueueSize`, `:13`). Removal happens only on
  registration (`addChannel`, `:67-70`) — there is no expiry, so for each *new* ID the attacker
  needs a fresh ID, which is exactly what the cap stops. Verified no other insertion path
  exists (`grep` for `danglingDgramQueues` → only `:56,61,67,69,87,94,100`).
* **Race between removal and re-registration:** both directions are decided under the same
  mutex: `addDanglingDatagramsQueue` re-checks `m.channels[id]` first (`:83-86`), and `addChannel`
  takes the queue out of the map and hands it to the channel in one locked step (`:65-72`).
  So a datagram that arrives after a channel registered goes to the channel, and one that
  arrives after a channel was pruned (`removeChannel`, `:114-118`) allocates a fresh — still
  capped — dangling queue. No path found that both removes and leaves a growing queue behind.
* **What happens at the bound:** the *datagram* is dropped with a warning (`:94-98`); nothing
  stalls, nothing is closed. Consequence: the bound is fail-closed for legitimate traffic
  (see F-15) rather than fail-safe.
* **Not a leak, but not reclaimed either:** the 256 slots are retained until the conversation
  dies; there is no per-entry drain on close and no TTL. That is F-15.

### 2.2 P4-02 — is the close listener actually invoked on all close paths?

`channelImpl.Close()` now calls the listener (`channel.go:487-497`). Findings:

* **Wiring:** the listener is a plain struct field set by `NewChannel` (`channel.go:309,330`);
  there is no registration step that can fail, and every one of the six construction sites on
  both the client and the server path passes the manager (`conversation.go:323,409,422,437,455`,
  `server.go:196`). A nil listener is guarded and pinned by `TestCloseWithoutListener`
  (`resources_manager_test.go:74-79`).
* **Normal FIN / handler teardown:** every handler family ends with a deferred `Close()` —
  `cmd/ssh3-server.go:201,268,850,1367-1368`, `client/client.go:202`,
  `cmd/sftp_subsystem.go:91,177`, `cmd/subsystem.go:88`, `client/reverse_forward.go:128`,
  `cmd/dynamic_forward_server.go:129`, `client/master.go:392` — so normal end-of-life prunes.
* **Refusal path:** the production refuser *does* tear the channel down —
  `cmd/ssh3-server.go:1282-1288` calls `channel.CancelRead(); channel.Close(); return false` —
  so a budget-refused channel is now pruned from the manager by the same `Close()` that fixes
  P4-02, and its `runningSessions` entry is removed by `admitSessionChannel` (P3-01). This is the
  claim the P4-02 commit message makes, and it holds — but only because `spawnChannel` closes the
  channel; the P4-03 test's stub `spawn` does not (see 2.3).
* **Panic path:** each handler body is wrapped in `util.PanicGuard` *and* carries
  `defer channel.Close()`, so a recovered panic still unwinds through the deferred close and
  prunes. Verified by reading the defer order; not exercised at runtime in this pass.
* **CancelRead path — genuinely not pruned.** `channelImpl.CancelRead()` (`channel.go:483-485`)
  only cancels the receive side; pruning is *not* part of it. Callers:
  `cmd/ssh3-server.go:254` (TCP write error) and `client/client.go:188` are covered by the
  sibling goroutine's `defer channel.Close()`; `cmd/dynamic_forward_server.go:241`,
  `client/session_pump.go:43` and `client/client.go:188`'s channel are teardown-shaped too.
  No *persistent* leak was found on the current call graph, but the invariant "cancelled ⇒
  pruned" does not exist — a future caller that cancels without closing still leaks, which is
  half the class P4-02 set out to close. Recorded as a PARTIAL in the table rather than a new
  finding.
* **Use-after-prune:** `channelsManager.getChannel` has exactly one consumer in the non-vendor
  tree — `Conversation.AddDatagram` (`conversation.go:502`). Stream data is read through the
  `Channel` object the handler already holds, so pruning removes no lookup any handler depends
  on. The one behavioural change is datagram routing, which is F-14.
* **Repeated close / idempotency:** `removeChannel` is a `delete` of a possibly-absent key under
  the mutex (`:114-118`); `TestCloseRemovesChannelFromManager`
  (`resources_manager_test.go:60-73`) pins a second `Close()` and asserts the send side closed
  twice. No re-registration path exists (QUIC stream IDs are never reused), so no
  "prune-then-resurrect" ambiguity.

### 2.3 P4-03 — does the regression test exercise the refusal path?

**Partly, and the gap matters.**

* What it *does* exercise: the real `admitSessionChannel` (`cmd/ssh3-server.go:126-145`) with the
  real `budget` type (`cmd/channel_budget.go:16-51`), asserting (a) the entry is visible to the
  spawner and survives admission, and (b) on refusal the entry is deleted and the run function
  never starts (`cmd/session_admission_test.go:36-80`).
* What it does *not* exercise: the production refusal path. `spawnChannel` is a closure created
  inside `ServerMain` (`cmd/ssh3-server.go:1282-1296`) and is not injectable, so the test's stub
  `spawn` never performs the real `tryAcquire` ordering, never calls `CancelRead`/`Close` on the
  channel and never touches the manager. The test therefore pins the *pairing* the refactor
  extracted — which is the regression P4-03 named — but not the production refusal behaviour,
  and a future change that moved the budget check or dropped the `channel.Close()` in
  `spawnChannel` would keep the test green.
* Also unexercised: `stubSFTPChannel` stands in for the channel, so the interaction between the
  refusal teardown and the P4-02 prune is untested end to end.

**Verdict: PARTIAL.** The refactor and the pin are real improvements; the "regression test for
the refusal path" claim is narrower than it reads.

### 2.4 P4-04 — is the local advertisement floored, and does it change the confirmation?

* Floored where it is used: `NewChannel` (`channel.go:313`) applies `clampLocalMaxPacketSize`
  (`:193-198`) before `buildHeader` and before `ChannelInfo` is filled (`:315-320`). Inbound
  channels already carry the peer value that `clampPeerMaxPacketSize` floored
  (`conversation.go:294`, `server.go:175`), so for them the call is a no-op.
* `WriteData` computes `emptyMsgLen`/`chunkSize` once and returns an error when
  `MaxPacketSize <= emptyMsgLen` (`channel.go:397-407`) — the zero-progress loop is gone on
  every path, not only the well-formed one.
* **Protocol confirmation: unchanged.** The confirmation value is the *conversation-level* local
  advertisement, not the channel advertisement: `AcceptChannel` calls
  `channel.confirmChannel(c.maxPacketSize)` (`conversation.go:481`) and
  `confirmChannel` puts that value in `ChannelOpenConfirmationMessage.MaxPacketSize`
  (`channel.go:434-440`). The floor never reaches that value. On the peer side the confirmation's
  value is discarded anyway (`channel.go:364-368` only sets `confirmReceived`), so there is no
  equality check to break.
* Net wire effect: zero for the shipped call sites (all pass 30000); for a hypothetical
  sub-4096 caller the header now advertises 4096 — the same value P3-02's peer-side floor already
  forced the acceptor to adopt, so the two ends stay consistent. Interop with a *different*
  implementation (Rust `crates/ssh3`, reference Go) was **not** exercised — no live peer in this
  pass; see Limitations.

## 3. Rust `crates/ssh3-server` — first-class review (static only)

**Toolchain limitation, stated up front:** `cargo` and `rustc` are not installed in this
environment (`which cargo rustc` → empty). Nothing in this section was compiled, linted
(clippy/`cargo-audit`) or executed. All of it is a read of the source at `e760a88`, and no
dynamic claim is made.

### 3.1 Unsafe inventory

Workspace-wide there are **16** `unsafe` occurrences (vs. the 16 the pass-1 anchor reported — no
change). `crates/ssh3-server/src/lib.rs` holds 8, all in one file:

| Line | Site | Assessment |
| --- | --- | --- |
| `312` | `unsafe extern "C" { fn crypt(..) -> *mut c_char }` (`#[link(name="crypt")]`, linux only) | Declaration; the call is wrapped in a process-wide `Mutex` (`320-323`, `378`) because `crypt(3)` returns a static buffer and is not reentrant — correct |
| `351` | `getspnam_r(username, &mut spwd, buf, buf.len(), &mut result)` | Bounded by the caller's buffer; ERANGE retry is bounded (below) |
| `366` | `shadow_entry.assume_init()` | Reached only when `status == 0`, where glibc's contract is "the struct was filled". Sound as written; the one place where a libc returning 0 without filling the struct would be UB |
| `371` | `CStr::from_ptr(sp_pwdp)` | Pointer is `is_null()`-checked at `367`, points into the same-iteration `buffer` (alive), and is NUL-terminated by construction |
| `379` | `crypt(password.as_ptr(), sp_pwdp)` | Inside the lock; both pointers are NUL-terminated `CString`s/glibc strings |
| `383` | `CStr::from_ptr(computed).to_owned()` | `computed.is_null()` checked at `380`; the copy happens **inside** the lock, so the static buffer cannot be clobbered before it is read — correct |
| `619` | `ioctl(master_fd, TIOCSWINSZ, &winsize)` | Standard pty winsize; `winsize` is a live local |
| `1409` | pty/ioctl region | **Not reviewed in this pass** (line-level read not reached) — carried forward as unreviewed |

The remaining 8 are client-side `crates/ssh3-client/src/lib.rs:147,563,585,590,2393,2408,2491`
(`BorrowedFd::borrow_raw`, `isatty`, `TIOCGWINSZ`, `kill`, one more fd/`ioctl` block) — not
enumerated past the line list in this pass.

### 3.2 `crypt(3)` / shadow FFI, bounds and lifetimes (`lib.rs:310-396`)

* **Input hygiene:** both username and password go through `CString::new` and an interior NUL is
  an error (`341-344`) — no silent truncation of a peer-supplied credential.
* **Buffer growth is bounded:** the `getspnam_r` loop starts at 1024 bytes, doubles on `ERANGE`,
  and stops retrying at 1 MiB, where it returns `Err(errno)` (`346-395`). At most ~11 iterations;
  `buffer` is a `Vec` reused across iterations, so no per-iteration leak and no unbounded spin.
* **Buffer alignment (new, Low/Info — F-17):** the buffer passed for `struct spwd` + strings is
  `vec![0u8; buffer_len]`, i.e. an alignment-1 allocation handed to a callee that stores a
  `struct spwd` in it. glibc's allocator returns ≥16-byte-aligned storage in practice, so this
  works today; it is under-typed and would be UB on a libc that wrote the struct with
  alignment-sensitive instructions. `Vec<spwd>` + a separate string buffer would be exact.
* **Returned C strings:** both `sp_pwdp` and crypt's return value are scanned for NUL
  (`CStr::from_ptr`), i.e. unbounded reads if the pointer were unterminated. Both come from
  glibc, which NUL-terminates; the failure mode that *can* happen (`crypt` → NULL) is checked at
  `380`. No peer-controlled pointer reaches either call.
* **Field lifetime/validity:** `sp_pwdp` points into the same-iteration `buffer`; every use
  (`to_bytes()` at `372`, `crypt` at `379`, the comparison at `386`) happens while `buffer` is
  still alive, so there is no dangling-struct-field window. `sp_pwdp == NULL` → `Ok(false)`
  (`367-369`). Locked/absent hashes (`!`/`*`) are rejected *before* `crypt` (`373-375`), so a
  shadow entry with no password cannot authenticate.
* **Error paths:** `status == 0 && result == NULL` → `Ok(false)` (`362-364`); `sp_pwdp == NULL` →
  `Ok(false)`; other non-zero status → `Err(errno)` (`394`); `crypt == NULL` →
  `Err(last_os_error())` (`380-382`). No allocation is leaked on any of them (the only owned
  allocation, the `CString`, is either returned or dropped), and no failure is silently turned
  into success.
* **Thread safety:** correct — one global mutex around `crypt`, copy-before-unlock.

### 3.3 `unwrap()`/`expect()`/`panic!` reachability

* 874 `.unwrap()` in the workspace, concentrated in `crates/ssh3-client/src/lib.rs` (502),
  `crates/ssh3-server/src/lib.rs` (136 unwrap/expect), `crates/ssh3-h3` (88),
  `crates/ssh3-quinn/src/channel.rs` (61), `crates/ssh3-auth` (30), `crates/ssh3-core` (12+9+6).
* **In the audited auth/FFI function there is exactly one** `unwrap()` — the `crypt_lock().lock()`
  at `378`. It panics only on a poisoned lock, i.e. after another thread already panicked inside
  a one-instruction critical section that contains no fallible code.
* Everything else in `default_password_verifier` returns `io::Result` and is fallible-safe.
* **Honest gap:** a site-by-site reachability triage of the remaining ~870 sites (parsers, wire
  decoding, QUIC/H3 handlers) is **not** possible in a static pass of this size and was **not**
  done here. Whether any of them is reachable from peer bytes **pre-auth vs post-auth** therefore
  remains unestablished; this is the largest single open item for the Rust server and the
  natural subject of a pass 6.

### 3.4 Auth-path parity with the Go server (pubkey / OIDC / password)

* **Password (Rust):** platform `crypt(3)`+shadow on Linux (`310-396`), optional
  `config.password_verifier` override (`335-337`), and `password_auth_available` gates whether
  password auth is offered at all (`335-337`). Two timing observations:
  * **F-16 (Low, pre-auth):** the hash comparison `computed_hash.as_c_str().to_bytes() ==
    stored_bytes` (`386`) is a short-circuiting byte compare, not constant-time; and `crypt()` is
    only reached after `getspnam_r` *found the user*, so response time separates an existing
    username from a nonexistent one. No lockout or rate-limit exists in this function; whether the
    caller applies one was **not verified** in this pass, so "lockout parity with the Go server"
    is **UNKNOWN**, not "missing".
* **Go server (comparison basis):** the shipped Windows/CI builds pass
  `-tags disable_password_auth` (`windows-client.yml:28,30`), and the release workflow installs
  `gcc libcrypt-dev` for the CGO amd64 build (`.github/workflows/release.yml:29-32`), i.e. the Go
  server does have a libc-coupled build variant. The Go vs Rust comparison was **not** performed
  line by line in this pass — flagged as remaining work rather than asserted.
* **Pubkey / OIDC paths (Rust):** `crates/ssh3-auth` (30 unwrap/expect) was not read in this pass.

### 3.5 Resource-limit parity (conversation cap, channel budget)

**NOT VERIFIED.** I did not gather line-level evidence for the Rust server's conversation cap or
channel budget in this pass, so I cannot say whether it enforces the S2-02/P4-class limits
(`maxChannelsPerConversation`, `userBudgets`, `maxConnections`) that the Go server enforces.
Stated as an open item; do not read this section as clearance.

## 4. Distribution / supply chain

What the release actually ships and what an attacker with repo write access can change:

* **Trigger and scope:** `.github/workflows/release.yml` runs on tag `v*` (`:6-9`), with
  `permissions: contents: write` (`:11-12`), `fetch-depth: 0` (`:24`), and
  `GITHUB_TOKEN: secrets.GITHUB_TOKEN` (`:40`) feeding `goreleaser/goreleaser-action@v6`
  (`:33-38`, `distribution: goreleaser`, `version: '~> v2'`, `args: release --clean`).
  `GOFLAGS: -mod=mod` (`:19`) — the vendored Rust h3 shim has no `modules.txt`.
* **Action pinning (F-18, Info):** every action is pinned by **major tag only** —
  `actions/checkout@v4`, `actions/setup-go@v5`, `goreleaser/goreleaser-action@v6`,
  `actions/upload-artifact@v4` (`build.yml:23,25`, `release.yml:22,26,34`,
  `test.yml:22,38`, `windows-client.yml:23,24,31`). Nothing is SHA-pinned, so a retagged upstream
  release can change what the release job executes; the job then publishes with
  `contents: write`.
* **Windows `.syso` (P4-05, still open):** `cmd/ssh3/rsrc_windows_amd64.syso` is a tracked opaque
  binary (`git ls-files '*.syso'`), regenerated by hand for 0.1.31 in `e760a88` (70882 → 57288
  bytes), and **no workflow or Makefile target regenerates or verifies it** (no `winres`/`rsrc`
  match under `.github/workflows/` or in `Makefile`). It is linked into the shipped Windows
  client: `windows-client.yml:28,30` build `./cmd/ssh3` for `GOOS=windows` amd64 **and** arm64,
  and goreleaser builds windows targets too (`.goreleaser.yaml:23,33`). Effect: a repo-write
  attacker can alter the resource blob and the release job will embed it in the artifacts with
  no diff a reviewer would notice beyond a byte count, and no CI step can reproduce or attest it.
  It is not code, but it is unreproducible shipped content — the cheapest available fix is to
  generate it in CI (or drop it), which would also remove the last hand-maintained binary.
* **Reproducibility:** the goreleaser config (`.goreleaser.yaml`) has `builds:`/`archives:`/
  `checksum: checksums.txt` (`:10-23,93-115`) and `ldflags` stanzas (`:46,67,90`); no
  `-trimpath`/`mod_timestamp` key matched my search, so build reproducibility is not configured —
  which is consistent with the `.syso` situation but was **not** verified key-by-key.
* **Artifact verification:** goreleaser's own `checksums.txt` is the only integrity artifact;
  there is no sigstore/cosign signing, no SBOM/provenance (no `sign`/`sbom` keys matched).
  `packaging/` (`postinst`, `prerm`, `ssh3-server.service`, `ssh3-server.env`) was listed but its
  contents were **not** reviewed in this pass.

## 5. New findings on changed code

| ID | Sev | Finding | Evidence |
| --- | --- | --- | --- |
| **F-14** | Low (post-auth) | **A single datagram for an unregistered channel kills the client conversation's whole datagram receive loop.** `Conversation.AddDatagram` returns `util.ChannelNotFound` for an unknown channel ID (`conversation.go:502-507`), and the client datagram loop treats *any* error as terminal — `log.Error` + `return` (`conversation.go:230-234`) — so every later datagram of every channel on that conversation is lost silently (the loop never restarts). The server-side twin already tolerates exactly this case: `server.go:317-323` logs a warning and continues. Pre-existing (`git blame` → `ca4da52`), but **P4-02 makes it reachable in normal operation**: an in-flight datagram for a channel that has just been closed/pruned is now `ChannelNotFound` instead of being queued on the still-registered channel, as it was before the fix. Fix direction: mirror `server.go:317-323` on the client path. | `conversation.go:230-234`, `:496-510`; `server.go:315-323` |
| **F-15** | Info (post-auth) | **The 256 dangling slots are never reclaimed**, so the P4-01 cap is fail-closed. A peer can pin all 256 with junk IDs for the conversation's lifetime (`resources_manager.go:94-98` drops only *new* IDs), after which every legitimate pre-registration datagram is dropped with a warning; nothing drains or ages an entry when a channel closes. Worst-case retention ≈ 256 × 64 datagrams × payload (QUIC's default max datagram payload puts a conversation in the tens of MB), per conversation. An LRU/TTL, or reclaiming entries on `removeChannel`, would keep the bound while restoring the race. | `resources_manager.go:79-105`, `:114-118` |
| **F-16** | Low (pre-auth) | **Rust password auth leaks timing**: the stored/computed hash comparison is a short-circuiting `==` (`lib.rs:386`), and `crypt()` runs only when `getspnam_r` resolved the user, so response time distinguishes existing usernames. No constant-time compare, no lockout inside the function (caller behaviour unverified). | `crates/ssh3-server/src/lib.rs:340-396` |
| **F-17** | Info | **Unaligned storage for `struct spwd`**: `vec![0u8; len]` (align 1) is handed to `getspnam_r`, which stores a `struct spwd` in it (`lib.rs:349-358`). Works with glibc's allocator, formally under-typed. | `crates/ssh3-server/src/lib.rs:346-359` |
| **F-18** | Info (supply chain) | **Actions pinned by major tag, not SHA**, on a job holding `contents: write`; no signing/SBOM/provenance in the release path; the committed `.syso` is unverifiable shipped content. | `.github/workflows/release.yml:11-12,22,26,34,40`; `windows-client.yml:23,24,31`; `cmd/ssh3/rsrc_windows_amd64.syso` |

No new finding was found in the P4-01 cap logic, in the P4-02 prune mechanics (idempotency,
locking, listener wiring), or in the P4-04 clamps.

## 6. Probes run

| Probe | Result |
| --- | --- |
| `go vet ./util/ ./message/` (Go 1.26.0 recovered from the module cache) | **clean** — no output, exit 0 |
| `go test ./util/ ./message/` | **pass** — `ok .../util`, `ok .../message` (cached results, no failure) |
| 30 s `FuzzParseSSHString` smoke | **NOT RUN** — not started before this report was written; no claim |
| Dynamic probe of the P4-01 bound | **NOT RUN** as a live test; the bound was verified statically plus by reading `TestDanglingDatagramQueuesBounded` (`resources_manager_test.go:26-35`), which drives the real `addDanglingDatagramsQueue` |
| `go test ./... ` / `-race`, full suite | **NOT RUN** in this pass (the fix commit reports them green; not re-verified here) |
| Rust: `cargo build/test/clippy` | **NOT POSSIBLE** — no cargo/rustc in the environment; static review only |

## 7. Coverage and limitations (honest)

**Covered in depth at `e760a88`:** the complete `dc1b8a4` diff and every line it touches
(`channel.go` clamps/`WriteData`/`Close`, `resources_manager.go` cap + prune, `cmd/ssh3-server.go`
`admitSessionChannel`/`spawnChannel`, both new test files, the CHANGELOG claims); the six
`NewChannel` call sites; the `Close`/`CancelRead` call graph; the datagram framing/routing path
(`conversation.go:496-510`, `server.go:315-323`); the Rust `crypt(3)`/shadow FFI block; the
release workflow, Windows build workflow and `.syso` provenance; the four commits in
`d9ea092..e760a88`.

**Not covered — do not read this report as clearance for any of these:**
1. **Rust `unwrap()`/`panic!` reachability from peer bytes** across `ssh3-proto`, `ssh3-core`,
   `ssh3-quinn`, `ssh3-h3`, `ssh3-client` (~870 sites) — the largest remaining item.
2. **Rust resource-limit parity** (conversation cap, channel budget) — no evidence gathered.
3. **Rust auth parity** beyond password: pubkey and OIDC (`crates/ssh3-auth` unread), and whether
   a lockout/rate-limit exists around `default_password_verifier`.
4. `crates/ssh3-server/src/lib.rs:1409` (the remaining server-side `unsafe`) and the 8 client-side
   `unsafe` sites (line list only).
5. **Cross-implementation interop of the P4-04 floor** with a live peer (Rust or reference Go) —
   reasoning only, no runtime exercise.
6. **`FuzzParseSSHString`, `go test ./...`, `-race`, and any dynamic/concurrent probe** — not run.
7. `packaging/` contents; the `.goreleaser.yaml` body key-by-key (builds/ldflags/archives were
   only spot-checked); `c4aea26` (sftp-client pipelining) and `d52a6c3` (client `Term`) remain
   as unreviewed leftovers from earlier passes.
8. Client-side findings from earlier passes (F-05, F-12, F-13) were **not re-walked** — their
   status is "unchanged code in this range", not "re-verified".

**Bottom line:** P4-01, P4-02 and P4-04 are genuinely closed, with two caveats worth acting on —
the cancel-without-close gap and F-14, which is the one regression the prune introduced into a
live code path. P4-03 is pinned more narrowly than claimed. P4-05 is **not** fixed: the release
still embeds a hand-committed binary blob into both shipped Windows architectures.
