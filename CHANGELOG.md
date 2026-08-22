# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Finished the S7 rollout across every surface, and gated it.** 3.3.0 shipped
  the scenario with the source, PoC, rules and main README updated — and left
  `challenges/`, `SECURITY.md`, `CONTRIBUTING.md`, `CITATION.cff` and `.github/`
  behind. The pre-ship check was scoped to the files that happened to be edited,
  which is exactly how a surface gets missed.

  One miss was **functional, not cosmetic**: each challenge's Setup command pins
  the *other* scenarios to `fixed` so its own mission has one answer. All six
  still pinned six toggles instead of seven, leaving S7 live — so S1's "find the
  one tool that lets you cross tenants" had two answers, and so did the rest.

  Also corrected: the README env-var table and all three all-fixed commands now
  carry `LAB_S7`; `challenges/README.md` has the S7 row and counts seven;
  `SECURITY.md`/`CONTRIBUTING.md`/`CITATION.cff` count seven planted flaws; the
  issue template's coverage number is 5-of-7 and its config link no longer points
  at a heading that does not exist; and `detection/README.md` lists all seven
  rules — the `-py-ternary` rule had been missing from that table since the
  previous release.

### Added

- **`test/docs-consistency.test.js`** — the durable fix. It derives the scenario
  list from the `LAB_S*` toggles the server actually reads, the tool count from
  the `registerTool` calls, and the rule ids from the ruleset, then checks the
  docs against them. Counting by hand is what failed, so nothing in it is counted
  by hand. Mutation-checked against the real defects: removing `LAB_S7` from a
  challenge Setup fails with *"that scenario stays vulnerable and this challenge
  has more than one answer"*; dropping the S7 table row or a toggle from an
  all-fixed command each fail too. Add an S8 and it names every file left behind.

  Suite is now 51 tests (was 42).

## [3.3.0] - 2026-08-22

### Added

- **Scenario S7 — "The Missing Key" (`note_get_by_query`).** The lab taught only
  one shape of object-authz bug: resolve an object by id, then forget a separate
  `requireOrgAccess()` call (S1). Real MCP servers rarely look like that. They
  bind the tenant into the query — `repo.findOneBy({ id, workspaceId })` — and
  the bug is quieter: the tenant key is simply left out of the filter. There is
  no guard call to be missing, which is exactly why a guard-call review walks
  past it. This is the shape **CVE-2026-54052** (n8n, CVSS 9.6) took. S7 plants
  that omission (`store.findNoteBy({ id })` in vuln, `{ id, orgId }` in fixed),
  with a challenge, a solution, a two-way PoC row, and three unit tests.

  The scenario was written after auditing four production MCP servers
  (activepieces, Directus, Flowise, n8n) for this class. All four were clean, and
  all four defend the same way — the tenant identity comes from the authenticated
  session and is bound into the query — which is now documented in
  `solutions/s7.md` as field-grounded "how real servers get this right."

- **Detection rule `mcp-unscoped-query-object-fetch`** for the S7 shape. It flags
  a repository fetch (`findOneBy` / `findOne({ where })` / `delete` / `softDelete`)
  whose filter carries an `id` but no tenant-shaped key, and stays silent when a
  tenant key (`workspaceId` / `projectId` / `orgId` / …) is bound. Unlike the
  other six rules it is **WARNING, not ERROR**: a single call cannot prove the
  entity is tenant-scoped, so it flags the shape for review rather than asserting
  a bug. Measured review rate on the four audited servers: 0 on activepieces and
  Directus, a handful each on Flowise and n8n that all resolved to safe on
  reading. Still **zero findings against the official `@modelcontextprotocol/sdk`**
  (168 files), so the headline benchmark holds across all seven rules.

### Changed

- CI's fixture-count gate moves 14 → 17 (11 JavaScript + 6 Python).
- Detection coverage against the lab's own runtime-toggle source is now **5 of 7
  scenarios** (S2, S3, S4, S6, S7); S1 and S5 remain uncaught for the reason
  `detection/README.md` documents.
- Version realigned to 3.3.0 across `package.json`, `package-lock.json` and
  `CITATION.cff` (they trailed at 3.2.0 while the last published tag was v3.2.1).

## [3.2.0] - 2026-08-22

### Added

- **Python coverage for three of the object-authz rules.** The reference MCP
  SDKs ship in TypeScript *and* Python, so a JavaScript-only ruleset could see
  at most half the ecosystem. `mcp-missing-object-authz-check`,
  `mcp-client-supplied-scope-overrides-session` and
  `mcp-wildcard-sentinel-scope-bypass` now declare `python`, each with a
  matching Python fixture carrying both the vulnerable and the guarded case.

  The other two rules (`mcp-batch-resolve-missing-per-item-scope-filter`,
  `mcp-admin-named-tool-missing-role-check`) stay JavaScript-only on purpose:
  their exclusions are written against `server.registerTool(...)` plus an
  arrow function, a shape that can never match Python. Declaring `python` on
  them would add patterns that cannot fire — coverage on paper, nothing in
  practice. Python equivalents need `@server.tool()`-shaped patterns and their
  own fixtures, which is separate work.

- **`mcp-client-supplied-scope-overrides-session-py-ternary`** — Python's
  `x if x else y`. The `or` spelling normalises to `||` and was already
  covered; this is the other idiomatic form of the same defect. It is a
  separate rule rather than another pattern on the shared one because a
  multi-language rule requires every pattern to parse in *every* declared
  language, and this one is not valid JavaScript. Adding it to the shared rule
  made that rule invalid — and the scan still exited 0 while silently losing
  six findings across both languages.

- **`detection/` — Semgrep static-analysis rules for the same bug class the
  challenges teach.** Six rules (`detection/semgrep/mcp-object-authz.yml`),
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

### Changed

- **`mcp-wildcard-sentinel-scope-bypass` now filters on the compared
  identifier.** Its pattern is `$PARAM == "*"`; `==` is JavaScript's secondary
  equality operator but Python's only one, so without a filter it matched any
  literal `"*"` comparison. Measured against a real 215-file Python MCP
  server: two findings, both a tokenizer doing `ch == "*"`, both false. The
  filter keeps the identifiers the rule's own message already names
  (`org_id`/`tenant_id`/`project_id`/`user_id`); both JavaScript call sites in
  this lab use `org_id`, so JS coverage is unchanged.

- **Every guard exclusion gained a `snake_case` twin.** The exemption list only
  knew `requireOrgAccess`-style names, so a correctly guarded Python handler
  calling `require_org_access(...)` was reported as vulnerable. A gate wider
  than the defect it targets gets switched off, which protects nothing.

- CI's fixture-count gate moves from 8 to 14 (8 JavaScript + 6 Python), and the
  job's display name loses its rule count entirely. Branch protection pins a
  required check by exact display name, so a name like "(5 rules x vuln/ok
  pair)" stops matching the moment a rule is added -- the check never reports
  and the default branch becomes unmergeable. The count belongs in the `want`
  assertion, where being wrong is loud.

### Verified

Measured, not asserted:

| target | before | after |
|---|---|---|
| fixtures (`ruleid:`/`ok:` annotations) | 8 JS | 8 JS + 6 Python, 26/26 annotations correct |
| official `@modelcontextprotocol/sdk`, 168 files | 0 findings | 0 findings |
| this lab's `src/` | 5 findings | 5 findings |
| a real 215-file Python MCP server | 2 findings, both false | 0 findings |

`semgrep --test` could not be used to check the annotations — it crashes with
an internal `IndexError` on this platform — so they were verified by walking
the fixtures and findings directly. A crashed test runner is not a passing one.

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
