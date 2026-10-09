# Security audit — pass 3 (fix verification)

**Repo:** `nagual2/ssh3-go` · **Audited HEAD:** `8725d65` (origin/main, v0.1.28) · **Baseline (pass 2):** `ff5ef77` (v0.1.27)
**Date:** 2026-10-09 · **Scope:** verification of the remediation series for the pass-2 findings + regression hunt on the changed code. Report-only; no code changes.

> Status: **work in progress** — sections are appended as the audit progresses.

## 1. Change set since the pass-2 baseline

```
8725d65 docs(changelog): restore newest-first section ordering
98f48da chore(release): bump software version to 0.1.28
73aecac fix(security): close the pass-2 audit findings (S2-01..S2-07)
c4aea26 feat(sftp): pipeline recursive transfers, 2000 files 25.9s -> 1.3s
10f72d1 Merge pull request #3 from nagual2/docs/security-audit-pass2
```

(todo: per-commit → finding mapping)

## 2. Pass-2 finding status

(todo)

## 3. Regression hunt on the fixes

(todo)

## 4. New findings on changed code

(todo)

## 5. Loose end from pass 2 (CLI `-L` channel-type string)

(todo)

## 6. Dynamic probes

(todo)

## 7. Coverage and limitations

(todo)
