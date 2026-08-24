# MCP Object-Authz Lab

[![lab-integrity](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> A small, self-hostable, **vulnerable-by-design** [MCP](https://modelcontextprotocol.io)
> server for learning how **object-level / cross-tenant authorization** bugs
> (BOLA / IDOR — [CWE-639](https://cwe.mitre.org/data/definitions/639.html),
> [CWE-862](https://cwe.mitre.org/data/definitions/862.html)) appear in Model
> Context Protocol tools, and how to hunt them.

It is a multi-tenant note server exposing fifteen MCP tools and one MCP resource
across **ten independent BOLA scenarios**. Each scenario is a different variant
of the same bug class, toggled by its own environment variable. Run them all at
once or isolate one at a time.

## Why this lab exists

Most MCP security attention goes to **prompt injection** and tool-poisoning.
Object-level authorization is a quieter, different class, and the usual
prompt-injection test suites and scanners do **not** find it. When an MCP server
is multi-tenant, every tool that resolves an object from a **client-supplied id**
must verify the caller is allowed to touch *that* object. Miss the check on a
single tool and you have a cross-tenant read, write, or delete — regardless of
how good the prompt-injection defenses are. Catching it takes *reading the
authorization on each tool*, which is exactly the muscle this lab trains.

This isn't theoretical. Asana's MCP connector (Jun 2025) leaked data across
tenant boundaries for roughly 1,000 customer organizations — a breakdown in
tenant isolation, the same shape of bug as S1-S7 below
([Pomerium's writeup](https://www.pomerium.com/blog/asanas-ai-connector-leak-exposed-sensitive-data-across-organizations-what-it-means-for-mcp-security)).
And n8n-mcp — a popular MCP server with 20k+ GitHub stars — shipped
[CVE-2026-54052](https://www.manifold.security/blog/n8n-mcp-idor-cross-tenant-credential-theft)
(CVSS 9.6): sequential integer ids on a table missing a tenant-id column let
any caller read or delete another tenant's stored API keys. Neither would
have been caught by a prompt-injection scanner — both are S1/S3-shaped bugs
(this lab's "missing check on one tool" and "list vs. get asymmetry"
scenarios), just in production instead of a lab.

## Try the challenges

Ten hands-on scenarios in [`challenges/`](challenges/README.md) — no hints
until you open [`solutions/`](solutions/). Each runs locally in under 5 minutes.

| Scenario | Pattern |
|---|---|
| [S1](challenges/s1.md) | Inconsistent authorization — find the single outlier |
| [S2](challenges/s2.md) | Client-supplied scope trusted as authorization |
| [S3](challenges/s3.md) | List→get asymmetry — batch skips per-object check |
| [S4](challenges/s4.md) | Wildcard/sentinel value bypasses scope filter |
| [S5](challenges/s5.md) | Role/token-type bypass — admin-named tool, no role check |
| [S6](challenges/s6.md) | Foreign-parent injection — create trusts a caller-supplied org |
| [S7](challenges/s7.md) | Unscoped query — tenant key omitted from the filter (the real-world shape) |
| [S8](challenges/s8.md) | Resource-URI-as-scope — the resources/read surface, not tools/call |
| [S9](challenges/s9.md) | Authz-from-client-round-tripped-value — an editable share grant |
| [S10](challenges/s10.md) | Forwarded-header-as-scope — a trusted request header (HTTP transport) |

## Quickstart (< 5 minutes)

Requirements: **Node.js ≥ 20**.

```bash
npm install
npm test    # 51 tests — auth.js/store.js in isolation, plus docs-consistency
npm run poc # 26-row two-way gate — the tools/resources wired end-to-end over MCP
```

Expected `npm run poc` output (26/26 rows, all scenarios + the hardened build):

```
MCP object-level authorization lab — two-way gate (10 scenarios + hardened build)

  SC   BUILD  ACTION                                         OUTCOME   EXPECT    OK
  S1   vuln   note_get    cross-tenant (Bob→Acme)            DENIED    DENIED    ✓
  S1   vuln   note_delete cross-tenant (Bob→Acme)            DELETED   DELETED   ✓
  S1   fixed  note_delete cross-tenant (Bob→Acme)            DENIED    DENIED    ✓
  S1   fixed  note_delete same-tenant  (Bob→Globex)          DELETED   DELETED   ✓
  S2   vuln   note_search  scope-as-param (Alice→org_globex) LEAKED    LEAKED    ✓
  S2   fixed  note_search  scope-as-param (Alice→org_globex) SCOPED    SCOPED    ✓
  S3   vuln   note_batch_get list→get asymm (Alice+Globex)   LEAKED    LEAKED    ✓
  S3   fixed  note_batch_get list→get asymm (Alice+Globex)   SCOPED    SCOPED    ✓
  S4   vuln   note_export  wildcard org_id='*' (Alice)       LEAKED    LEAKED    ✓
  S4   fixed  note_export  wildcard org_id='*' (Alice)       SCOPED    SCOPED    ✓
  S5   vuln   note_admin_get cross-org as Bob (user)         LEAKED    LEAKED    ✓
  S5   fixed  note_admin_get cross-org as Bob (user)         DENIED    DENIED    ✓
  S5   fixed  note_admin_get cross-org as Dana (real admin)  ALLOWED   ALLOWED   ✓
  S6   vuln   note_create_in_org org_id=org_globex (Alice)   INJECTED  INJECTED  ✓
  S6   fixed  note_create_in_org org_id=org_globex (Alice)   SCOPED    SCOPED    ✓
  S7   vuln   note_get_by_query cross-tenant (Alice→Globex)  LEAKED    LEAKED    ✓
  S7   fixed  note_get_by_query cross-tenant (Alice→Globex)  DENIED    DENIED    ✓
  S8   vuln   resources/read cross-tenant (Alice→Globex)     LEAKED    LEAKED    ✓
  S8   fixed  resources/read cross-tenant (Alice→Globex)     DENIED    DENIED    ✓
  S9   vuln   note_share_redeem tampered grant (Alice→Globex) LEAKED    LEAKED    ✓
  S9   fixed  note_share_redeem tampered grant (Alice→Globex) DENIED    DENIED    ✓
  S9   fixed  note_share_redeem own grant     (Alice→Acme)   ALLOWED   ALLOWED   ✓
  S10  vuln   note_get_scoped X-Org-Id=org_globex (Alice over HTTP) LEAKED    LEAKED    ✓
  S10  fixed  note_get_scoped X-Org-Id=org_globex (Alice over HTTP) SCOPED    SCOPED    ✓
  ALL  fixed  11 cross-tenant routes (Bob→Acme)              BLOCKED   BLOCKED   ✓
  ALL  fixed  legitimate access (Dana admin + Bob own note)  ALLOWED   ALLOWED   ✓

  Two-way gate: PASS (26/26 rows OK)
```

The PoC is a real MCP client. It spawns the server over stdio (**locally — no
network, no third party**) and runs a *two-way gate* per scenario: in the **vuln**
build the exploit succeeds; in the **fixed** build it is blocked and legitimate
same-org access still works (no false positive).

The final `ALL` rows apply that same two-way discipline to the whole server at
once — every scenario `fixed`, every cross-tenant route closed, and legitimate
access (an admin's cross-org read, a user's own note) still working. Each S1-S9
arm deliberately pins one toggle and leaves the rest at their `vuln` default, so
without these rows the hardened build the section below tells you to run would
have no coverage at all.

---

## Scenario S1 — Missing org-scope check (the original)

**Tool:** `note_delete`  
**Class:** CWE-639 / CWE-862 — object-level authorization  
**Toggle:** `LAB_MODE` / `LAB_S1`

Among the six core note tools, every one that resolves an object by a
client-supplied `id` calls `requireOrgAccess()` to confirm the note belongs to
the caller's org — except `note_delete` (in vuln mode), so **any caller can
delete any org's note** by knowing or guessing its id.

**Challenge:** The six core note tools are `note_list`, `note_get`,
`note_create`, `note_update`, `note_delete`, `note_search`. Exactly one lets a
caller in one org delete another org's note. Which one, and what makes it
different?

> The server exposes twelve tools in total; the other six belong to S3-S7 and
> are vulnerable in their own default state. Run
> [`challenges/s1.md`](challenges/s1.md)'s Setup command, which pins them to
> `fixed`, or this scenario has more than one answer.

<details>
<summary>Hint</summary>

Three tools take a client-supplied `id` (`note_get`, `note_update`, `note_delete`).
Two of them call `requireOrgAccess()` after resolving the note. One does not.
</details>

<details>
<summary>Answer</summary>

`note_delete`. It resolves the note exactly like `note_get` and `note_update`,
but in `LAB_MODE=vuln` it never calls `requireOrgAccess(session, note)`. The fix
is that one line — the same check its siblings already perform. See the comment
block in [`src/tools.js`](src/tools.js) above `note_delete`.
</details>

---

## Scenario S2 — Scope-as-param

**Tool:** `note_search`  
**Class:** CWE-639 — client-supplied scope parameter trusted as authorization  
**Toggle:** `LAB_S2`

`note_search` accepts an optional `org_id` parameter, documented as "admin use."
In vuln mode the server uses it unconditionally — any caller can set it to any
other org's id and receive that org's notes. The server authenticates *who you
are* correctly, but then trusts the caller's assertion about *whose data to return*.

**Challenge:** Alice (org Acme) calls `note_search`. How does she read Globex's
notes without knowing any note ids, using only one tool?

<details>
<summary>Hint</summary>

Look at the `note_search` input schema. There is a parameter that is supposed to
be admin-only. What happens if you supply it as an ordinary user?
</details>

<details>
<summary>Answer</summary>

Alice calls `note_search` with `org_id="org_globex"`. In `LAB_S2=vuln` the server
substitutes her session's `orgId` with the supplied value and returns Globex's notes.
The fix: in `LAB_S2=fixed` the `org_id` parameter is accepted (removing it would
be a breaking API change) but silently ignored; `session.orgId` is always used.
</details>

---

## Scenario S3 — List→get asymmetry

**Tool:** `note_batch_get`  
**Class:** CWE-862 — inconsistent authorization between list and fetch  
**Toggle:** `LAB_S3`

`note_list` safely returns only the caller's org's notes. But `note_batch_get`
accepts an array of explicit ids and resolves each one directly from storage
*without re-applying the org scope check*. An attacker who knows (or guesses)
note ids from another org can mix them into the batch and receive them.

**Challenge:** Alice can call `note_list` and gets only her own notes. She
suspects the ids from other orgs are guessable (they are: `n_acme_1`,
`n_globex_1`, …). How does she read a Globex note?

<details>
<summary>Hint</summary>

`note_batch_get` accepts a list of ids. What happens when you mix ids from
different orgs in the same request?
</details>

<details>
<summary>Answer</summary>

Alice calls `note_batch_get` with `ids: ["n_acme_1", "n_globex_1"]`. In
`LAB_S3=vuln` both are resolved and returned — the batch skips per-object org
checks. The fix: in `LAB_S3=fixed` the resolved notes are filtered to
`session.orgId` before returning, so `n_globex_1` is silently dropped.
</details>

---

## Scenario S4 — Wildcard/sentinel bypass

**Tool:** `note_export`  
**Class:** CWE-639 — sentinel value short-circuits scope filter  
**Toggle:** `LAB_S4`

`note_export` exports all notes for a given org. A magic sentinel value (`"*"` or
`"all"`) is documented as "admin only" for a global export. In vuln mode the
server honors it from **any** authenticated caller — letting them dump every note
from every tenant in a single call.

**Challenge:** Alice wants to export data from all three orgs (Acme, Globex,
Initech) in one call. She has only a user-level token. How?

<details>
<summary>Hint</summary>

Read the `note_export` tool description. There is a "magic value" mentioned.
What happens if a non-admin user passes it?
</details>

<details>
<summary>Answer</summary>

Alice calls `note_export` with `org_id="*"`. In `LAB_S4=vuln` the server
recognizes the sentinel and calls `store.listAllNotes()` — returning all 6 notes
from all 3 orgs. The fix: in `LAB_S4=fixed` the `org_id` parameter is ignored
entirely; the server always exports only `session.orgId`.
</details>

---

## Scenario S5 — Role/token-type bypass

**Tool:** `note_admin_get`  
**Class:** CWE-863 — role/token-type bypass  
**Toggle:** `LAB_S5`

The tool is named and documented as admin-only. In vuln mode nothing actually
checks that the caller holds the admin role — any valid token reaches the
cross-org lookup. Naming a tool `admin_*` is documentation, not enforcement.

**Challenge:** Bob (org Globex, an ordinary user) wants to read Acme's note
`n_acme_1` using an "admin" tool he was never granted access to. How?

<details>
<summary>Hint</summary>

Bob's own token is unprivileged. Does `note_admin_get` actually verify that
before resolving the note?
</details>

<details>
<summary>Answer</summary>

Bob calls `note_admin_get` with `id="n_acme_1"` using `bob-token`. In
`LAB_S5=vuln` the server resolves and returns the note — it never checked
whether Bob's session role is `"admin"`. The fix: `LAB_S5=fixed` calls
`requireAdminRole(session)` before the lookup; ordinary tokens are denied,
while Dana's real admin token (`dana-token`) still succeeds. See
[`src/auth.js`](src/auth.js)'s `requireAdminRole()` and the comment block
above `note_admin_get` in [`src/tools.js`](src/tools.js).
</details>

---

## Scenario S6 — Foreign-parent injection

**Tool:** `note_create_in_org`  
**Class:** CWE-639 — client-supplied parent/org trusted on create  
**Toggle:** `LAB_S6`

A cross-team collaboration tool lets a caller create a note "inside" a
specified org. In vuln mode the server trusts the caller-supplied `org_id`
with no membership check — any caller can inject a note into an org they do
not belong to. Unlike S1-S5 (all reads or a delete), this is a **write-side**
BOLA: it poisons another tenant's data instead of leaking it.

**Challenge:** Alice (org Acme) wants to plant a note that shows up in
Globex's `note_list`, despite never being a Globex member. How?

<details>
<summary>Hint</summary>

`note_create_in_org` takes an `org_id` parameter. What org does the note
actually end up in if Alice supplies someone else's?
</details>

<details>
<summary>Answer</summary>

Alice calls `note_create_in_org` with `org_id="org_globex"`. In
`LAB_S6=vuln` the note is created with `orgId: "org_globex"` — it will show
up the next time Bob calls `note_list` or `note_search`, despite Alice never
being a Globex member. The fix: `LAB_S6=fixed` still accepts `org_id` in the
schema (removing it would be a breaking change, same convention as S2/S4)
but ignores it; the note is always created inside `session.orgId`.
</details>

---

## Scenario S7 — Unscoped query

**Tool:** `note_get_by_query`  
**Class:** CWE-639 — tenant key omitted from a scoped query  
**Toggle:** `LAB_S7`

S1's outlier is a **missing guard call**: resolve a note by id, then forget to
call `requireOrgAccess`. Real MCP servers rarely look like that. They bind the
tenant *into* the query — `repo.findOneBy({ id, workspaceId })` — so there is no
separate guard line to omit. The bug in that world is quieter: the tenant key is
simply left out of the filter, and the query matches on `id` alone.

This is the shape **CVE-2026-54052** (n8n, CVSS 9.6) took — a table fetched by a
sequential id with the tenant column left out of the `WHERE`, letting any caller
read another tenant's stored secrets. It is also the pattern this lab's own
detection rule (`mcp-unscoped-query-object-fetch`) was written to catch, because
a guard-call detector never sees it: there is no guard call to be missing.

**Challenge:** Alice (org Acme) wants to read a Globex note by its id through
`note_get_by_query`, despite never being a Globex member. Why does it work?

<details>
<summary>Hint</summary>

The tool resolves the note through a filtered query. What does the filter
contain in vuln mode — and what one key is missing from it?
</details>

<details>
<summary>Answer</summary>

In `LAB_S7=vuln` the tool calls `store.findNoteBy({ id })` — the filter carries
only the caller-supplied `id`, so the query matches any note with that id
regardless of org, and Alice reads Globex's note. The fix (`LAB_S7=fixed`) binds
the tenant key into the same query: `store.findNoteBy({ id, orgId: session.orgId })`,
so a cross-org id resolves to nothing. Note there is no `requireOrgAccess` call
in either build — the authorization *is* the tenant key in the filter, which is
exactly why the S1-style "look for the missing guard" reflex walks past it.
</details>

---

## Scenario S8 — Resource-URI-as-scope

**Resource:** `note://{token}/{orgId}/{noteId}`
**Class:** CWE-639 — a caller-writable URI segment trusted as scope
**Toggle:** `LAB_S8`

S1-S7 are all tools (`tools/call`). This one lives on `resources/*`, a
separate MCP primitive with its own registration API, its own handler
signature (`(uri, variables)` instead of a single args object), and its own
client-side call (`resources/read`). A review that reads "every tool" never
sees it.

The resource template turns the tenant into a URI path segment — which the
*caller* writes. In vuln mode the handler trusts that segment as the scope.
Identity still comes from the `{token}` segment, resolved through the same
`resolveSession()` every tool uses; only the *scope* segment is the planted
bug. It is also quieter than a tool-call exploit: many MCP hosts gate tool
calls behind an approval prompt but treat a resource read as inert reference
material, with lighter or no approval at all.

**Challenge:** Alice (org Acme) wants to read a Globex note through
`resources/read`, despite never being a Globex member, and without calling a
single tool.

<details>
<summary>Hint</summary>

The URI template has three variables: `token`, `orgId`, `noteId`. One is who
you are. One is what you want. What is the third one actually used for?
</details>

<details>
<summary>Answer</summary>

In `LAB_S8=vuln` the handler reads `note://alice-token/org_globex/n_globex_1`,
resolves Alice's session from `token`, then uses the `orgId` *path segment* —
not the session's own org — as the scope: `store.findNoteBy({ id: noteId,
orgId })`. The fix (`LAB_S8=fixed`) ignores that segment and uses
`session.orgId` instead. The URI template still carries `{orgId}` in both
builds — removing it would be a breaking template change — it is simply never
trusted as authorization.
</details>

---

## Scenario S9 — Authz-from-client-round-tripped-value

**Tools:** `note_share_prepare`, `note_share_redeem`
**Class:** CWE-639 — a value round-tripped through the client trusted as authorization
**Toggle:** `LAB_S9`

`note_share_prepare` is correctly authorized: it mints an opaque grant for a
note the caller's own session can already access. `note_share_redeem` decodes
that grant and serves whatever note id is inside it — on the assumption that
"the grant must have come from an authorized tool." The grant is a plain
client-side string between the two calls, with no cryptographic signature; a
caller can decode it, edit it, and redeem the edited version.

This is the shape a tool-chaining flow takes in MCP specifically: there is no
server-side continuity between two `tools/call` invocations. Every value that
crosses the gap between them travels through the client — and in an agentic
pipeline, through the calling model's own context, where it can be edited or
mangled without any deliberate tampering at all. "A prior tool already
checked this" is a client-side claim, not a server-verified fact.

**Challenge:** Alice (org Acme) prepares a share grant for her own note. She
never authenticates as anyone else. How does she end up reading Globex's note?

<details>
<summary>Hint</summary>

Look closely at what `note_share_prepare` actually returns. Is it opaque, or
does it just look opaque?
</details>

<details>
<summary>Answer</summary>

The grant is base64url-encoded JSON, not a signed token. Alice decodes it,
finds `{"noteId": "n_acme_1"}`, rewrites it to `{"noteId": "n_globex_1"}`,
re-encodes it, and calls `note_share_redeem` with the tampered grant. In
`LAB_S9=vuln` the tool resolves and returns whatever note the decoded grant
names, with no re-check against Alice's session. The fix (`LAB_S9=fixed`)
treats the decoded value as a hint, not an authorization: it calls
`requireOrgAccess(session, note)` on the resolved note before returning it —
the same object-level check every other scenario in this lab teaches, applied
at the point a round-tripped client value is trusted again.
</details>

---

## Scenario S10 — Forwarded-header-as-scope

**Tool:** `note_get_scoped`  **Class:** CWE-639 / CWE-290 — a client-supplied request header trusted as scope  **Toggle:** `LAB_S10`  ·  **Transport:** HTTP only (`src/http-server.js`)

Every other scenario reads its scope from a tool argument or a resource URI.
S10 reads it from an HTTP request **header**. Over the streamable-HTTP transport
the SDK hands each tool call the request headers in `extra.requestInfo.headers`,
and `note_get_scoped` trusts an `X-Org-Id` header — "set by the gateway" — as the
org scope. But any client talking to the server directly sets that header
itself, so it is client-controlled input wearing the costume of infrastructure.
This is the transport-layer sibling of S2, and the real-world class of
*trusting `X-Forwarded-For` for a security decision* (the IP-scoping variant is
the same bug, same fix). Because stdio carries no request headers, the bug only
exists in the HTTP deployment — which is why S10 ships its own
`src/http-server.js`, and why a review that only exercises the stdio server
never sees it.

**Challenge:** You are Alice (`alice-token`, org Acme). Connect an MCP client to
`http://127.0.0.1:3010/mcp` and read Globex's notes using one extra request
header. See [`challenges/s10.md`](challenges/s10.md).

---

## Detection rules — automate the hunt

[`detection/`](detection/README.md) ships 14 [Semgrep](https://semgrep.dev)
rules — one per code shape above, with Python siblings where the JavaScript
spelling cannot parse as Python — that flag these patterns in **your own**
MCP server source, not just this lab's. **Nine of the fourteen run against
Python as well as JavaScript/TypeScript**, which matters because the
reference MCP SDKs ship in both.

Honestly documented, and re-measured in this release: the earlier claim that
the rules "catch 5 of 7 scenarios" against this lab's own source implied the
S1/S5 rules miss real-world bugs. They do not. On production-shaped files —
no toggle, guard simply absent — both fire exactly as designed; the only code
they go quiet on is a handler where the guard is *written but gated behind a
runtime toggle*, i.e. this lab's own scaffolding (see the linked README for
the measured decision and the fixtures pinning it). With S8 and S9 added, the
current measurement against this lab's own source is **7 of 9 scenarios
flagged (S2, S3, S4, S6, S7, S8, S9)** — S1 and S5 are the only two still
missed, for that same toggle-blindness reason. S9 has no dedicated rule: the
existing `mcp-missing-object-authz-check` (S1's rule) already catches its
vulnerable shape, since the fix path is a plain `$OBJ = store.get...(); ...;
return ok($OBJ)` span with no guard call in between — see
[`detection/README.md`](detection/README.md) for the measured caveat (it
only catches the assignment-carrying spelling, not an inline
`return ok(store.getNote(...))` with no local variable). Against the
official `@modelcontextprotocol/sdk` the ruleset produces **zero findings**,
measured with a planted canary proving the scan actually reached the tree
(semgrep silently skips `node_modules`, so an unverified `0` is not a
result).

One of those five is worth spelling out, because it was wrong until 3.4.0. S6
appeared covered: scans reported a finding inside `note_create_in_org`. What
matched was this lab's own `modes.s6 === "vuln" ? … : …` toggle, a line no
production server writes. Against four real spellings of the same bug the
whole ruleset returned nothing. `mcp-write-parent-from-client-argument` catches
the shape itself, and the fixture keeps proxy and target apart on purpose.

Drop it into your own MCP server's CI as a GitHub Action. Findings upload to
your repo's Security tab, so the calling workflow needs
`security-events: write`:

```yaml
permissions:
  security-events: write   # only needed for the SARIF upload

steps:
  - uses: WRG-11/mcp-objauthz-lab@main
    with:
      path: src/   # your MCP server source
```

## How it is built

| File | Role |
|---|---|
| [`src/store.js`](src/store.js) | In-memory multi-tenant seed data: 3 tenant orgs (*Acme/Alice*, *Globex/Bob*, *Initech/Carol*, 2 notes each) + 1 admin org (*Platform Ops/Dana*, no notes). |
| [`src/auth.js`](src/auth.js) | `resolveSession(token)` → server-trusted `{ user, org, role }`; `requireOrgAccess(session, object)` — the object-level check; `requireAdminRole(session)` — the role check. |
| [`src/tools.js`](src/tools.js) | Fourteen tools plus one resource (`note://{token}/{orgId}/{noteId}`). Nine planted-bug handlers (one per scenario, S1-S9). |
| [`src/server.js`](src/server.js) | Stdio MCP server. Reads `LAB_MODE`/`LAB_S1..S9` env vars, passes a `modes` object to `registerTools`. |
| [`poc/exploit.js`](poc/exploit.js) | MCP client running the 24-row two-way gate: all 9 scenarios in isolation, plus the all-`fixed` hardened build. |
| [`test/`](test/) | `node --test` unit tests for `auth.js`/`store.js` in isolation (42 tests, no MCP transport involved) plus `docs-consistency.test.js`. |

**Identity model (deliberate simplification).** Each tool takes a bearer `token`
the server resolves to a fixed user, org, and role. The caller never asserts its
own org or role — only presents a token. In a production MCP server this identity
would come from the transport / OAuth layer; the lab passes it per call so it
stays a single process and the authorization logic is explicit and easy to read.

---

## Environment variables

Each scenario is controlled by an independent env var (all default to `"vuln"`):

| Var | Controls | Vuln behaviour | Fixed behaviour |
|---|---|---|---|
| `LAB_MODE` / `LAB_S1` | S1 — `note_delete` | Cross-tenant delete succeeds | `requireOrgAccess()` blocks it |
| `LAB_S2` | S2 — `note_search` | `org_id` param overrides session scope | `org_id` ignored; session scope always used |
| `LAB_S3` | S3 — `note_batch_get` | All resolved notes returned regardless of org | Notes filtered to `session.orgId` |
| `LAB_S4` | S4 — `note_export` | `org_id="*"/"all"` dumps all tenants | `org_id` ignored; own org only |
| `LAB_S5` | S5 — `note_admin_get` | No role check; any token reaches cross-org lookup | `requireAdminRole()` blocks non-admins |
| `LAB_S6` | S6 — `note_create_in_org` | `org_id` param trusted as write target | `org_id` ignored; note created in session's own org |
| `LAB_S7` | S7 — `note_get_by_query` | tenant key omitted from the query filter; any org's id resolves | `orgId` bound into the same filter |
| `LAB_S8` | S8 — `note://` resource | `orgId` URI path segment trusted as scope | URI segment ignored; session's own org used |
| `LAB_S9` | S9 — `note_share_redeem` | decoded grant's `noteId` trusted with no session re-check | `requireOrgAccess()` re-checked against the resolved note |

Run all scenarios in their fixed state:

```bash
# Linux / macOS
LAB_S1=fixed LAB_S2=fixed LAB_S3=fixed LAB_S4=fixed LAB_S5=fixed LAB_S6=fixed LAB_S7=fixed LAB_S8=fixed LAB_S9=fixed LAB_S10=fixed npm start

# Windows PowerShell
$env:LAB_S1='fixed'; $env:LAB_S2='fixed'; $env:LAB_S3='fixed'; $env:LAB_S4='fixed'; $env:LAB_S5='fixed'; $env:LAB_S6='fixed'; $env:LAB_S7='fixed'; $env:LAB_S8='fixed'; $env:LAB_S9='fixed'; npm start
```

Isolate one scenario (e.g. test only S2):

```bash
LAB_S2=vuln LAB_S1=fixed LAB_S3=fixed LAB_S4=fixed LAB_S5=fixed LAB_S6=fixed LAB_S7=fixed LAB_S8=fixed LAB_S9=fixed LAB_S10=fixed npm start
```

---

## Hunt checklist — object-level authorization in MCP

Use this when auditing a real multi-tenant MCP server (one you own or are
authorized to test). The bug class is "the server authenticates *who you are*
but forgets to check *whether you may touch this object*":

- [ ] **Client-supplied scope trusted as authorization (→ S2).** A tool takes an
  `org_id` / `project_id` / `tenant_id` argument and uses it to *scope the query*
  instead of *checking it against the caller's membership*.
- [ ] **Membership check decoupled from object resolution.** The tool verifies
  the caller belongs to some org/project, but loads the object by a *different* id
  without confirming the object lives under that membership.
- [ ] **Inconsistent authorization — the single outlier (→ S1).** Most object
  tools check; one or two do not. Read **every** tool that resolves an object by id.
  The forgotten one is usually a less-glamorous verb (`delete`, `archive`, `export`).
- [ ] **Reads guarded, mutations not.** `get`/`list` are scoped but `update`/`delete`
  slipped through — or vice-versa.
- [ ] **Wildcard / sentinel short-circuit (→ S4).** A special value (`'all'`,
  `'*'`, empty, `0`, `null`) skips the scope filter entirely.
- [ ] **Role / token-type bypass (→ S5).** An "admin" or "service" code path
  skips the per-object check.
- [ ] **List → get asymmetry (→ S3).** `list` only returns your org's objects, so
  ids feel "private" — but `get`/`batch-get` accept *any* id and the ids are
  guessable or enumerable.
- [ ] **Create/update accepting a foreign parent (→ S6).** `create(parent_id=…)`
  accepts a parent the caller is not a member of, injecting an object into
  another tenant.
- [ ] **Resource URI segment trusted as scope (→ S8).** A `resources/read`
  handler binds a tenant/scope key straight from a URI template variable
  instead of the session — easy to miss because a review that only reads
  `tools/*` handlers never looks at `resources/*` at all.
- [ ] **A value round-tripped through the client trusted as authorization
  (→ S9).** A tool decodes a token/grant/cursor produced by an earlier tool
  call and serves the object it names, with no re-check against the current
  session — "an earlier tool already authorized this" is a client-side
  claim, not a server fact, and it is not fixed by making the value
  cryptographically signed if the redeeming tool never re-checks it.

The exploit primitive is always the same: authenticate as tenant **B**, call the
suspect tool with an object or scope that belongs to tenant **A**, and see whether
you get **A**'s data (or mutate it). Confirm a fix the same way the PoC here does
— **two-way**: the cross-tenant call must be blocked *and* the legitimate
same-tenant call must still succeed.

---

## Safety / scope

- **Vulnerable by design.** Do **not** deploy this on a reachable network or use
  it as a starting point for real code. Run it locally for learning only.
- **Synthetic.** All orgs, users, notes, and tokens are made up. There is no
  real data, no real target, and the PoC never makes a network request — it only
  spawns the local server process over stdio.

## Contributing

The most useful contribution to a detection ruleset is a **false positive** —
a rule that fires on correctly authorized code. A gate wider than the defect
it targets gets switched off, and a switched-off rule protects nothing, so
those are treated as real defects here. Misses are just as welcome; the rules
catch 7 of the 9 scenarios against this lab's own source and
[`detection/README.md`](detection/README.md) says why.

There is an issue template for each. [`CONTRIBUTING.md`](CONTRIBUTING.md) has
the fixture convention, the exact-count CI gate, and the multi-language rule
trap that costs an afternoon if you meet it the hard way.

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
Security reports go through [`SECURITY.md`](SECURITY.md) — and please do not
report the planted flaws; they are the point.

## Citing this

[`CITATION.cff`](CITATION.cff), or use GitHub's **Cite this repository** button.

## License

[MIT](LICENSE).
