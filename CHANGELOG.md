# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.11.1] - 2026-09-06

`v3.11.0` shipped with `CITATION.cff` still naming **3.5.0** -- six minor
versions behind. That was corrected on `main` after the release, which fixes
the repository but not the artefact: anyone citing the published `v3.11.0` tag
still reads a version that predates the SARIF export, the authorization-chain
evidence and the five-language corpus.

A patch release is the only way that correction reaches the tag.

### Fixed

- `CITATION.cff` names 3.11.1 and is now checked mechanically against
  `package.json`. The check compares the two versions directly rather than
  scanning for a leftover old string -- a scan only works between a bump and a
  release, and goes blind exactly when the tag catches up, which is how this
  drifted for six minor versions without anything objecting.

### Also on main since 3.11.0, not requiring a release of their own

- `CODEOWNERS` added -- the last community surface this repo was missing.
- `zod` 4.4.3 -> 4.5.4 (dependabot).

## [3.11.0] — 2026-09-05

The PoC's findings become machine-readable: an authorization **chain** is now
emitted as structured evidence and exported as SARIF, so a finding carries the
sequence that produced it rather than just the endpoint that failed.

### Added

- **Authorization-chain events.** The PoC emits each step of an authorization
  decision, so a finding can be read as a sequence (which call, with whose
  token, resolving which object) instead of a single endpoint verdict.
- **MCP chain-event identification** — chain events are tagged with the MCP
  operation that produced them, which is what makes a multi-step finding
  attributable rather than merely observed.
- **Machine-readable evidence export** (`--json-output`) and **SARIF export**
  (`--sarif-output`), so a lab run can feed a code-scanning pipeline or any
  SARIF viewer. README documents both flags.

### Changed

- Lab test and PoC output counts re-synced with what the code actually
  produces; `test/docs-consistency.test.js` keeps that claim mechanical rather
  than hand-maintained.

### Note

These shipped in #38 but only reached the counter line of `[3.10.0]`; the
features themselves were never described in a changelog entry and the version
did not move. This section is that entry, and `package.json` moves with it.

## [3.10.0] — 2026-08-25

### Added

- **Scenario S12 — Batch/bulk endpoint BOLA** (CWE-639 / CWE-862): new
  `note_batch_resolve` tool resolves a batch of note ids without a per-item
  org-scope filter — the "list→get asymmetry" at batch scale. Semgrep rule
  `mcp-batch-resolve-missing-per-item-scope-filter` (+ `-py`).
- **Scenario S13 — JWT/token scope confusion** (CWE-290): new
  `note_get_by_token_scope` tool trusts a caller-supplied `scope`/`aud`
  parameter as the authorization scope. Extended
  `mcp-client-supplied-scope-overrides-session` (+ `-py-ternary`) to cover it.
- **Real-capture corpus signatures for five languages** (Java, C#, Ruby, PHP,
  Kotlin) replacing the earlier placeholder S7/S10 patterns — drawn from public
  MCP-SDK / framework source. Kotlin S10 (`KtorServer.kt` header → transport) is
  the canonical cell; Ruby is an ideal same-repo FIRE/SILENT canary; PHP S10 is
  lowered to a documented taint recommendation (header-source → auth-sink).

### Changed

- Now **13 scenarios** (S1–S13), **18 tools** + 1 resource, **40 detection
  rules** across the `detection/semgrep/` directory (JS/TS + Python siblings +
  Go, Rust, Kotlin, Java, Ruby, PHP, C#, Swift language packs).
- CI fixture-finding count: **42 → 66**.
- PoC two-way gate: **38/38 rows** (13 scenarios + hardened build); unit tests: **52**.
- `SECURITY.md`: **13 planted flaws** (S1–S13).

## [3.8.1] — 2026-08-25

### Fixed

- **`mcp-ratelimit-scope-from-forwarded-header` (+ `-py`) now fires on real-capture fixtures.** The S11 rule's `pattern-either` structure was tuned to match the actual SurfSense audit pattern: optional-chained header access (`extra?.requestInfo?.headers?.["x-forwarded-for"]`) with nullish coalescing (`?? session.userId`) assigned to a variable, then used in quota/rate-limit store calls (`store.getQuotaCount(quotaKey)`, `store.isRateLimited(rateLimitKey)`). Block patterns matching the function body now correctly bind the header variable across assignment and use sites. Two-way canary verified:
  - FIRE: `xff-for-ratelimit.js` — all three quota/rate-limit vulnerability cases match (3 findings)
  - SILENT: `xff-for-logging.js` — XFF read for logging only produces zero findings
- CI fixture count updated: 39 → 42 (3 new S11 JS findings)

## [3.8.0] — 2026-08-24

### Added

- **Scenario S11 — X-Forwarded-For quota/rate-limit bypass**, the quota/rate-limit
  sibling of S10 on the **HTTP transport surface**. The new `note_create_limited`
  tool enforces a per-client creation quota (max 3 notes). In vuln mode the
  quota key is the `X-Forwarded-For` header — any caller can spoof it to reset
  their quota and create unlimited notes. In fixed mode the quota is keyed to
  the server-trusted session (`session.userId`). Real-world source: audit found
  SurfSense `rate_limiter.py` using XFF as the client identity for rate limiting.
  (CWE-639 / CWE-290.)
- `src/tools.js`: new `note_create_limited` tool with XFF-based quota (vuln) vs
  session-based quota (fixed). `src/store.js`: `getQuotaCount`/`incrementQuota`
  methods for the quota surface.
- Detection rules `mcp-ratelimit-scope-from-forwarded-header` (+ `-py` FastMCP
  sibling) plus real-capture fixtures. They key on quota/rate-limit header names
  (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`) used as the key for a quota
  or rate-limit counter; a non-quota header read for logging stays silent — the
  two-way canary.
- `challenges/s11.md` + `solutions/s11.md`. S11's challenge Setup uses the HTTP
  server; every other challenge's Setup now also pins `LAB_S11=fixed`.

### Fixed

- **`mcp-authz-scope-from-request-header` (+ `-py`) hardened against false positives.**
  The rule previously fired on ANY read of a scope-shaped header (`X-Forwarded-For`,
  `X-Org-Id`, ...). Now it REQUIRES the header value to reach an AUTHORIZATION
  DECISION (a store/list call that selects tenant scope, or an orgId binding in
  a query), not merely be read into a variable. Two-way canary verified:
  - FIRE: `const org = headers["x-org-id"]; return listNotesByOrg(org)` (scope decision)
  - SILENT: `const ip = headers["x-forwarded-for"]; logger.info(ip)` (logging only)
- **`mcp-wildcard-sentinel-scope-bypass` hardened against false positives.**
  The rule previously fired on ANY `"*"`/`"all"` comparison with a scope-like
  parameter name. Now it REQUIRES the wildcard to be in an AUTHORIZATION BYPASS
  CONTEXT (it gates scope widening, returns all tenants' data), not a textual
  comparison. Two-way canary verified:
  - FIRE: `if (scope === "*") return allOrgsNotes()` (authz bypass)
  - SILENT: `text.replace(/\*(.+?)\*/, "<b>$1</b>")` (markup) or UI search filter

### Changed

- Rule count 22 → 24 (+2 S11). Fixture finding count updated for new fixtures
  and hardened rules. Scenario count 10 → 11; tool count 15 → 16
  (`note_create_limited`). PoC two-way gate 26 → 28 rows (two S11 arms, run
  over a real HTTP round-trip with spoofed XFF). `docs-consistency.test.js`
  accepts an `http-server.js` Setup command and counts up to 16 tools + 1 resource.
- Real-capture fixtures added: `xff-for-logging.js/.py` (SILENT for S10 rule),
  `wildcard-in-markup.js` (SILENT for S4 rule), `xff-for-ratelimit.js` (FIRE
  for S11 rule) — minimal/anonymized patterns from the 9-repo audit.

Verified before release: 51 unit tests, PoC two-way gate 28/28 rows (incl. the
S11 HTTP arm proving a spoofed `X-Forwarded-For` bypasses quota in vuln and is
ignored in fixed), and `semgrep --config detection/semgrep/` gives correct
findings with 0 parse errors across all four languages.

## [3.7.0] — 2026-08-24

### Added

- **Scenario S10 — Forwarded-header-as-scope**, the lab's first scenario on the
  **HTTP transport surface**. Over the streamable-HTTP transport the SDK hands
  each tool call the request's headers in `extra.requestInfo.headers`. The new
  `note_get_scoped` tool trusts an `X-Org-Id` header — "set by the gateway" — as
  the org scope, but any client talking to the server directly sets that header
  itself. It is the transport-layer sibling of S2 (scope-as-param) and the
  real-world class of *trusting `X-Forwarded-For` for a security decision*.
  Because stdio carries no headers, S10 only manifests over HTTP — so it ships
  its own `src/http-server.js`, and a stdio-only review never sees it.
  (CWE-639 / CWE-290.)
- `src/http-server.js` — a minimal streamable-HTTP entry point running the same
  tools and store, the transport S10 needs. `guard()` now forwards the SDK's
  `extra` (RequestHandlerExtra) so a handler can reach `requestInfo`.
- Detection rules `mcp-authz-scope-from-request-header` (+ `-py` FastMCP
  sibling) plus fixtures. They key on the header **name**, so a non-scope
  header (`X-Request-Id`) read for logging stays silent — the two-way canary.
- `challenges/s10.md` + `solutions/s10.md`. S10's challenge Setup uses the HTTP
  server; every other challenge's Setup now also pins `LAB_S10=fixed`.

### Changed

- Rule count 20 → 22 (+2 S10). Fixture finding count 41 → 44 (23 JavaScript +
  15 Python + 3 Go + 3 Rust). Scenario count 9 → 10; tool count 14 → 15
  (`note_get_scoped`). PoC two-way gate 24 → 26 rows (two S10 arms, run over a
  real HTTP round-trip with a spoofed header). `docs-consistency.test.js` now
  accepts an `http-server.js` Setup command and counts up to 16 tools.

Verified before release: 51 unit tests, PoC two-way gate 26/26 rows (incl. the
S10 HTTP arm proving a spoofed `X-Org-Id` reads cross-org in vuln and is ignored
in fixed), and `semgrep --config detection/semgrep/` gives 44 findings with 0
parse errors across all four languages.

## [3.6.0] — 2026-08-24

### Added

- **Scenario S8 — Resource-URI-as-scope**, the lab's first scenario on the
  `resources/read` MCP primitive instead of `tools/call`: a `note://{token}/{orgId}/{noteId}`
  resource template whose handler trusts the `orgId` URI path segment as the
  authorization scope. Every prior scenario (S1-S7) is a tool; `resources/*`
  has its own registration API, its own handler signature (`(uri, variables)`
  instead of a single args object), and its own client call — a review that
  reads "every tool" never sees this surface. It is also quieter than a
  tool-call exploit in practice: MCP hosts commonly gate tool calls behind an
  approval prompt while treating a resource read as inert.
- Detection rule `mcp-resource-uri-variable-used-as-scope` (S8) plus its
  `-py` FastMCP sibling — a resource/tool-agnostic `$VAL` axis borrowed from
  S6's rule: session-derived scope stays silent, a caller-supplied URI
  variable used as the scope fires.
- Fixture `resource-uri-variable-used-as-scope.js`/`.py` — one vulnerable
  case, the fixed sibling, and a legitimate sibling whose URI template
  carries no tenant segment at all.
- `challenges/s8.md` + `solutions/s8.md`.
- **Scenario S9 — Authz-from-client-round-tripped-value**, on the tool-
  chaining surface: `note_share_prepare` mints a correctly-authorized opaque
  grant for the caller's own note; `note_share_redeem` decodes it and serves
  whatever `noteId` is inside, with no re-check against the redeeming
  session. The grant is plain base64url JSON with no signature, so no
  cryptography is needed to tamper with it — decode, edit `noteId`,
  re-encode. MCP tool chains have no server-side continuity between two
  `tools/call` invocations; every value crossing that gap travels through
  the client (and, in an agentic loop, through the calling model's own
  context).
- `challenges/s9.md` + `solutions/s9.md`.
- Go language pack: three `-go` rules covering S1, S2, and S7 for MCP
  servers built on `modelcontextprotocol/go-sdk`, in their own file
  (`detection/semgrep/mcp-object-authz-go.yml`) since Go's syntax (no
  `||`/ternary, PascalCase/camelCase casing) can't parse as JavaScript or
  Python.
  - `mcp-missing-object-authz-check-go` (S1) — the guard-call exemption
    list carries both exported and unexported spelling of each guard name.
  - `mcp-client-supplied-scope-overrides-session-go` (S2) — Go's zero-value
    fallback idiom, the language's spelling of the override this rule's
    JS/PY siblings catch via `||`/ternary.
  - `mcp-unscoped-query-object-fetch-go` (S7) — the struct/ORM primary-key
    lookup idiom (`db.First(&x, id)`). WARNING, same honesty as its
    siblings, and an explicit gap: a raw-SQL-string lookup is not covered
    (see `detection/README.md`).
- Rust language pack: three `-rust` rules covering S1, S2, and S5 for MCP
  servers built on the `rmcp` crate, in their own file
  (`detection/semgrep/mcp-object-authz-rust.yml`). Semgrep's Rust support was
  verified to parse the real `rmcp` handler idiom
  (`Parameters(T { .. }): Parameters<T>` destructuring on a `#[tool_router]`
  impl) before the rules were written.
  - `mcp-missing-object-authz-check-rust` (S1) — the `let`-bound fetch/mutate
    sequence, guard-call exemptions in snake_case.
  - `mcp-client-supplied-scope-overrides-session-rust` (S2) — a
    client-destructured scope field reaching the sink in place of the
    session's own; anchored name regex keeps a session field access silent.
  - `mcp-admin-named-tool-missing-role-check-rust` (S5) — an admin-named
    `#[tool]` async fn whose body never calls a role check.

### Changed

- The Semgrep scanner (`action.yml`, CI, and the contributor docs) now loads
  the whole `detection/semgrep/` directory instead of the single
  `mcp-object-authz.yml` file, so per-language rule files (Go, Rust, and any
  future language) load automatically without re-touching the shared entry
  point. `docs-consistency.test.js` enumerates rule ids across all `*.yml`
  files accordingly.
- Rule count 12 → 20; Python-carrying rules 8 → 9. Fixture finding count
  33 → 41 (21 JavaScript + 14 Python + 3 Go + 3 Rust) — S8 adds exactly one
  ruleid line per language (JS/Python), the Go pack three and the Rust pack
  three. S9 adds no fixture: measured against a probe file, the existing
  `mcp-missing-object-authz-check` (S1's rule) already catches its
  assignment-carrying vuln shape.
- `src/tools.js` now registers one MCP resource and two more tools (fourteen
  total) alongside the original twelve. `src/server.js` reads `LAB_S8` and
  `LAB_S9` alongside `LAB_S1..LAB_S7`.
- `poc/exploit.js`'s two-way gate grows from 19 to 24 rows (two S8 rows,
  three S9 rows; the `ALL`-fixed cross-tenant-route count grows from 9 to 11
  to include the resource read and the tampered-grant redeem).
- Running the ruleset against this lab's own `src/` now flags 7 of 9
  scenarios (S2, S3, S4, S6, S7, S8, S9) instead of 5 of 7 — S1 and S5 remain
  the only two missed, for the same toggle-blindness reason documented in
  `detection/README.md`.

Verified before release: 51 unit tests (including `docs-consistency.test.js`),
PoC two-way gate 24/24 rows, fixture scan 41/41 matching `ci.yml`'s `want`,
dogfood scan against `src/` 7 → 10 findings (did not drop), and zero findings
across the official `@modelcontextprotocol/sdk` with a planted canary proving
the scan reached that tree.

## [3.5.0] — 2026-08-23

### Added

- Four `-py` sibling rules, closing the last JavaScript/TypeScript-only shapes.
  The reference MCP SDKs ship in both languages; eight of the twelve rules now
  cover Python:
  - `mcp-batch-resolve-missing-per-item-scope-filter-py` (S3) — the batch
    resolve as a list comprehension (`[store.get_note(i) for i in ids]`);
    `.map` with an arrow has no Python spelling.
  - `mcp-admin-named-tool-missing-role-check-py` (S5) — FastMCP registers
    tools as decorated functions, so this sibling keys on the function name
    carrying `admin` and the body lacking a role check.
  - `mcp-unscoped-query-object-fetch-py` (S7) — `filter_by(id=...)` with no
    tenant kwarg and primary-key `session.get(Model, pk)`. A Model-name
    constraint keeps `config.get("timeout", 30)`-style `dict.get` calls
    silent (measured). WARNING like its JS sibling.
  - `mcp-write-parent-from-client-argument-py` (S6) — the kwargs spelling of
    the foreign-parent create/save. As predicted, the JS rule's core object-
    literal pattern cannot parse as Python, so it ported as a sibling rather
    than a merged rule.

### Fixed

- **`mcp-missing-object-authz-check`'s read branch had never fired on
  anything.** `patterns` is an AND: the `$MUTMETHOD` regex sat at top level,
  so when `pattern-either` took the read branch (`resolve -> get ->
  return ok(obj)`) the metavariable was never bound and the match died.
  Measured before the fix: every pure-read spelling of a cross-tenant fetch
  returned **zero** findings while the mutation was caught. The branches are
  now scoped blocks carrying only their own constraints, the read branch is
  anchored at the session-resolution line (required for its exclusions to
  engage — see below), and fixture pairs pin both halves: the caught read
  and the guarded read, in JavaScript and Python.
- **False positive on the official SDK, found by widening the measurement.**
  Scanning the full shipped `@modelcontextprotocol/sdk` tree (344 files,
  `dist/` included — earlier releases had measured a narrower subset) surfaced
  two findings from `mcp-batch-resolve-missing-per-item-scope-filter`, both
  the same shape: `relatedIds.map(id => this._requestResponseMap.get(id))` —
  an in-memory response-map lookup, not a storage resolve. Receivers ending
  in a container-ish suffix (map/cache/memo/index) are now excluded from both
  batch rules; everything else, including `this.store`-shaped receivers,
  still matches. Re-measured after the fix: zero findings, with a planted
  three-violation canary inside the copied tree firing 3/3 — proving the scan
  reached the code rather than silently skipping it (`node_modules` is
  skipped even under `--no-git-ignore`; an unverified `0` is not a result).
- **The README claim that the S1/S5 "miss" was "a real limitation, not a lab
  artifact" was wrong.** Measured on production-shaped files with the toggle
  stripped out: both rules fire exactly as designed. They go quiet only where
  a guard is written but gated behind a runtime toggle — this lab's own
  scaffolding shape. Decision, taken deliberately and pinned by new fixtures
  (`toggle-blindness.js`): the rules do NOT see through toggles. Treating a
  conditionally-present guard as absent would flag
  `if (config.strictAuthz) requireAccess(...)` — a legitimate production
  pattern, textually indistinguishable from the lab's toggle at this matching
  depth. A gate that wide produces the false positives that get a rule
  switched off.

### Changed

- Rule count 8 → 12; Python-carrying rules 3 → 8. Fixture finding count
  21 → 33 (20 JavaScript + 13 Python), including two deliberate second
  signals: unguarded admin handlers are flagged both for the missing role
  check and, via the now-live read path, for the missing object check —
  two true findings about one handler.

Verified before release: 51 unit tests, PoC two-way gate 19/19 rows, all four
acceptance gates green, and zero findings across the official
`@modelcontextprotocol/sdk` — with a planted canary proving the scan reached
that tree rather than silently skipping it.

## [3.4.0] — 2026-08-23

### Added

- Detection rule `mcp-write-parent-from-client-argument` (S6) — a `create`/`save`
  whose parent or tenant key comes from a caller-supplied argument instead of the
  session, with no membership check on it. Every other rule in the set guards a
  read; this one guards a write, and the asymmetry is the point: a caller who
  cannot read another tenant's data may still be able to create data inside it.
  WARNING rather than ERROR, for the same reason S7's rule is: bound straight
  from an argument it is a true positive, bound through a local the variable's
  origin decides and one call site cannot show it.
- Fixture `write-parent-from-client-argument.js` — four vulnerable spellings
  (bare argument, argument via a local, `args.workspaceId`, ORM `save` binding
  `tenantId`) and three correct ones, including a cross-team tool that accepts a
  destination and verifies membership first. Flagging that last one would be the
  false positive that gets the rule switched off.

### Fixed

- `detection/README.md` claimed `mcp-client-supplied-scope-overrides-session`
  covered S6. Measured, it does not. It fires inside `note_create_in_org`, which
  is why the scenario looked covered — but what it matches is this lab's own
  `modes.s6 === "vuln" && org_id ? org_id : session.orgId` toggle, a line no
  production server writes. Run against four real-world spellings of S6 the
  full seven-rule set returned **zero findings**. The claim is corrected and the
  scenario now has a rule that measures its actual shape.

### Changed

- Fixture finding count 17 → 21 (15 JavaScript + 6 Python); rule count 7 → 8.

Verified before release: 51 unit tests, PoC two-way gate 19/21 rows unchanged at
19/19, fixture annotations 4 of 4 `ruleid:` firing and 0 of 3 `ok:` firing, and
zero findings across the 336 JavaScript/TypeScript files of the official
`@modelcontextprotocol/sdk` — with a planted canary proving the scan reached
that tree rather than silently skipping it.

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
