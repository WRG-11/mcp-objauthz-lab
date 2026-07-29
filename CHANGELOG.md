# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`detection/` — Semgrep static-analysis rules for the same bug class the
  challenges teach.** Five rules (`detection/semgrep/mcp-object-authz.yml`),
  one per code shape from S1-S6 (S2/S6 share a rule — same shape, different
  tool), each with a matching vuln/ok fixture pair in
  `detection/semgrep/fixtures/`. Complements the hands-on lab: the
  challenges train a human to read tool handlers; this is the automatable
  half a CI pipeline or pre-commit hook can run against a real MCP server's
  source. Honestly documented limitation (`detection/README.md`): against
  this lab's own `src/tools.js` (vuln/fixed gated by a runtime `LAB_MODE`
  toggle in the same function, not separate files) the rules catch S2/S3/
  S4/S6 but miss S1/S5 — both rely on "no authz call appears between lookup
  and sink," and in `tools.js` the call *does* appear, just behind an `if
  (modes.sN === "fixed")` runtime condition a non-dataflow static rule can't
  evaluate. Real limitation, not a lab artifact — any codebase with a
  feature-flagged authz check has the same blind spot for this rule shape.
- CI: new `detection-rules` job runs the ruleset against its own fixtures
  and asserts the expected finding count, so a future edit that silently
  breaks a rule (over- or under-matching) fails the build the same way a
  broken two-way-gate row would.

### Fixed

- **Challenge setups did not isolate their scenario, which made S1
  unanswerable.** Every `LAB_S*` toggle defaults to `vuln` when unset, so
  `challenges/s1.md`'s Setup (`LAB_MODE=vuln node src/server.js`) left all six
  bugs live. Measured against that exact command, an ordinary user (`bob-token`,
  org Globex) reached Acme's data through **six** tools — `note_delete`
  (intended), plus `note_admin_get`, `note_batch_get`, `note_search`,
  `note_export` and `note_create_in_org` — while S1 asks the reader to "find the
  **one** tool". S1 is also the only challenge that does not name its tool up
  front (`Tool under test: One of the six core note tools`), so it is the one
  that actually depends on the isolation. A learner who reached for
  `note_admin_get` first got a working exploit and the wrong answer. Every
  challenge's Setup now pins the other five to `fixed`.
- `challenges/README.md` said "Each scenario is isolated: setting `LAB_S2=vuln`
  does not affect S1/S3/S4/S5/S6." True of the toggles, but it reads as though
  the others are off; they default to `vuln`. Reworded with the reason.
- `src/server.js` advertised a hardcoded MCP version of `3.0.0` while
  `package.json` was `3.1.0` — and the handshake value is the only one a client
  ever sees. The version is now read from `package.json`, so the two cannot
  drift apart again.
- Stale comments from the four-scenario era, none of which matched the code:
  `src/tools.js` ("4 independent BOLA scenarios" above an inventory of six),
  `poc/exploit.js` ("four independent BOLA scenarios" in a file that runs six),
  `src/auth.js` ("the bug is a tool that forgets to call it", singular),
  `.github/workflows/ci.yml` (described only the S1 gate), `SECURITY.md` (the
  count was corrected in 3.0.0 but the prose two lines below still said "the
  planted authorization bug"), and `solutions/s1.md` ("Five tools are correct").

### Added

- **Two-way gate now covers the all-`fixed` hardened build (`ALL` rows, 15 → 17).**
  Each S1-S6 arm pins one toggle and leaves the other five at their `vuln`
  default — that is what makes them isolated, and it is also why the build the
  README tells readers to run for a hardened server had no coverage at all. The
  new arm asserts both halves on the whole server: nine cross-tenant routes as
  an ordinary user are all blocked, and legitimate access (Dana's admin
  cross-org read, Bob's own note) still works.
- Verified by mutation, not assertion: disabling S4's fix so only the `"all"`
  sentinel leaks leaves **both** S4 rows green (that arm only tries `"*"`) while
  the `ALL` row reports `OPEN=1` and the gate exits 1. Disabling S5's fix is
  likewise caught. The hardened build itself was measured clean before the arm
  was written — this closes a coverage gap, not a live bug.

## [3.1.0] - 2026-07-16

Unit tests for the pure business logic (no tool/protocol surface change).

### Added
- `test/auth.test.js` — 16 tests for `resolveSession()`, `requireOrgAccess()`,
  `requireAdminRole()`, covering the edge cases the PoC's happy-path
  scenarios don't reach directly (unknown/empty token, null/undefined
  object, null/undefined session, error-message content).
- `test/store.test.js` — 23 tests for every `createStore()` method
  (org/user/note lookups, create/update/delete, org-scoped search),
  including the case-insensitive search and the type-guard on
  `updateNote()`'s patch fields.
- `npm test` (`node --test`, Node's built-in runner — no new dependency)
  wired into CI as its own step, ahead of the two-way gate.

### Notes
- These test the pure `auth.js`/`store.js` functions directly, independent
  of the MCP transport. `poc/exploit.js`'s two-way gate remains the
  end-to-end proof that the tools in `src/tools.js` actually call these
  checks correctly; the two suites are complementary, not redundant.

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
