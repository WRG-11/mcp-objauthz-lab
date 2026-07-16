# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-07-16

Two new independent BOLA scenarios closing the two hunt-checklist patterns
that had no runnable example (role/token-type bypass, foreign-parent
injection). Server bumped to v3.0.0; `LAB_S1`-`LAB_S4` behavior unchanged.

### Added
- **S5 — Role/token-type bypass** (`LAB_S5`): new tool `note_admin_get` is
  named and documented as admin-only but in vuln mode never checks the
  caller's role — any valid token reaches the cross-org lookup. Fix:
  `requireAdminRole(session)` runs first; a real admin token still succeeds
  (no over-block).
- **S6 — Foreign-parent injection** (`LAB_S6`): new tool
  `note_create_in_org` accepts an `org_id` parameter; in vuln mode the
  server trusts it as the write target with no membership check, letting a
  caller inject a note into an org they do not belong to. Unlike S1-S4
  (read/delete leaks), this is a write-side BOLA. Fix: `org_id` accepted in
  the schema but ignored; the note is always created inside
  `session.orgId`.
- Fourth identity **Dana** (`dana-token`, `role: "admin"`, org *Platform
  Ops*) added to `store.js`/`auth.js` — the only session S5's fixed build
  authorizes.
- `requireAdminRole()` helper in `auth.js` — the check S5's vuln build
  skips.
- Two-way gate expanded to 15 rows (3 for S5, 2 for S6).

### Changed
- `resolveSession()` now returns a `role` field (`"user"` for the three
  original tenants, `"admin"` for Dana).
- README hunt-checklist bullets for role-bypass and foreign-parent
  injection now link to their scenario (previously listed with no runnable
  example).
- `SECURITY.md` corrected: was still describing "one intentionally planted
  flaw" since the v1.0.0 wording, stale since the v2.0.0 (S2-S4) expansion.

## [2.0.0] - 2026-06-24

Three new independent BOLA scenarios, each gated by its own env var.
Server bumped to v2.0.0; `LAB_MODE` backward-compatible (still controls S1).

### Added
- **S2 — Scope-as-param** (`LAB_S2`): `note_search` accepts an optional `org_id`
  parameter that in vuln mode overrides the session's org scope. Any caller can
  supply any other org's id and receive that org's notes. Fix: `org_id` is
  accepted in the schema but silently ignored; `session.orgId` is always used.
- **S3 — List→get asymmetry** (`LAB_S3`): new tool `note_batch_get` resolves a
  list of note ids directly from storage without re-applying an org scope check.
  An attacker who guesses or learns foreign note ids can mix them into a batch
  request. Fix: resolved notes are filtered to `session.orgId` before returning.
- **S4 — Wildcard/sentinel bypass** (`LAB_S4`): new tool `note_export` accepts an
  `org_id` parameter; in vuln mode the sentinel values `"*"` / `"all"` dump all
  notes from all tenants regardless of who is calling. Fix: `org_id` ignored;
  always exports the caller's own org.
- Third tenant **Initech** (user Carol, `carol-token`, two notes) added to `store.js`
  and `auth.js` to make the wildcard and batch scenarios meaningful.
- `store.listAllNotes()` helper for the S4 exploit path.
- Two-way gate expanded to 10 rows (4 rows per scenario for S1, 2 rows each for
  S2/S3/S4). `poc/exploit.js` now uses per-scenario env overlays via
  `withServer(env, fn)`.

### Changed
- `registerTools(server, store, mode)` → `registerTools(server, store, modes)`
  where `modes = { s1, s2, s3, s4 }`. Each is independently `"vuln"` or
  `"fixed"`.
- `server.js` reads `LAB_S1`/`LAB_S2`/`LAB_S3`/`LAB_S4` (+ `LAB_MODE` as
  backward-compat alias for S1) and logs active modes to stderr on startup.
- README expanded with per-scenario challenge / hint / answer sections and an
  updated env-var reference table.

### Notes
- **Backward compatible**: existing `LAB_MODE=vuln/fixed` behavior (S1 only) is
  unchanged. New scenarios default to `vuln` when their env var is absent.

## [1.0.0] - 2026-06-10

Initial public release — a self-hostable, synthetic vulnerable MCP server that
teaches the object-level / cross-tenant authorization bug class (BOLA / IDOR,
CWE-639 / CWE-862): the "inconsistent-authorization single-outlier" pattern.

### Added
- Two-tenant MCP server (`src/`) with a single planted cross-tenant outlier:
  `note_delete` is missing the object-level ownership check that its scoped
  sibling tools enforce, so a caller from one tenant can delete another tenant's
  object — while the sibling read tool correctly denies the same cross-tenant
  access (proving a single outlier, not a globally broken server).
- `LAB_MODE` toggle (`vuln` / `fixed`) — the one-line fix that closes the outlier.
- Runnable two-way-gate PoC (`poc/exploit.js`): the `vuln` build reproduces the
  cross-tenant delete with the sibling read still denied; the `fixed` build blocks
  the cross-tenant delete without over-blocking the same-tenant one. Exit 0 only
  when all four checks match.
- README hunt checklist for finding this bug class in real-world MCP servers.
- `SECURITY.md`, MIT `LICENSE`.

### Notes
- This repository is **intentionally vulnerable** for education and detection
  research. Do not deploy it as a real service.
