# Security Audit — ssh3-go (Go implementation)

**Audit date (UTC):** 2026-10-06
**Audited revision:** `00c2f4697307c0b201e5d416bb0dfbe382998c78` (`origin/main`, tag `v0.1.26`)
**Scope:** static, report-only security audit of the Go implementation (`cmd/`, `client/`, `client_auth/`, `server_auth/`, `auth/`, `message/`, `util/`, `sftp` paths, forwarding, config parsing, client-side trust) plus a review of the Rust workspace (`crates/`) at the same revision.
**Method:** manual source review with `git grep` sweeps for panic/unsafe/unwrap surfaces, call-graph reachability analysis, dependency/CVE cross-check, plus local unit-test/fuzz runs. No dynamic exploitation of live systems.
**Out of scope:** fixing anything (this report is recommendations only), the C17 rewrite (`project/ssh3-c`), third-party `vendor/h3` patch internals (reviewed only at its integration boundary).

> STATUS: **IN PROGRESS** — this file is being committed incrementally while the audit proceeds. Sections marked *(pending)* are not yet written and must not be read as "clean".

## Findings table *(pending)*

## Executive summary *(pending)*

## Verified clean *(pending)*

## Dependencies / CVE notes *(pending)*

## Limitations *(pending)*

## Coverage *(pending)*
