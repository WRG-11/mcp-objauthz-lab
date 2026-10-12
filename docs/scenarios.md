# Scenario walkthroughs

One section per scenario, each a variant of the same bug class. A section opens
with its tool, weakness class and toggle, then walks from a challenge to the answer
with a hint on the way. To work a scenario without spoilers, start from
[`challenges/`](../challenges/README.md).

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

> The server exposes eighteen tools in total; six of them belong to S3-S7 and
> are vulnerable in their own default state. Run
> [`challenges/s1.md`](../challenges/s1.md)'s Setup command, which pins them to
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
block in [`src/tools.js`](../src/tools.js) above `note_delete`.
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
[`src/auth.js`](../src/auth.js)'s `requireAdminRole()` and the comment block
above `note_admin_get` in [`src/tools.js`](../src/tools.js).
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
header. See [`challenges/s10.md`](../challenges/s10.md).

---

## Scenario S11 — Forwarded-header quota bypass

**Tool:** `note_create_limited`  **Class:** CWE-639 / CWE-290 — a client-supplied request header keys a rate limit  **Toggle:** `LAB_S11`  ·  **Transport:** HTTP only (`src/http-server.js`)

S11 is the quota sibling of S10. `note_create_limited` allows three notes per
client, and the vulnerable build decides *which client* from the
`X-Forwarded-For` request header. A caller who has used up the quota sends a
new header value and is, as far as the server can tell, a new client. The fixed
build keys the quota to the session user, so the header no longer changes whose
quota is counted. Like S10, the bug needs request headers and therefore only
exists over HTTP.

**Challenge:** You are Alice (`alice-token`), already at the three-note limit.
Create a fourth note with one extra request header. See
[`challenges/s11.md`](../challenges/s11.md).

---

## Scenario S12 — Batch resolve without a per-item check

**Tool:** `note_batch_resolve`  **Class:** CWE-639 / CWE-862 — a multi-object endpoint without a per-item tenant filter  **Toggle:** `LAB_S12`

`note_batch_resolve` takes a list of note ids and resolves each one. The
vulnerable build returns every note it finds; the fixed build drops any
resolved note whose `orgId` is not the caller's. Unlike S3 there is no sibling
"list" tool to compare against — the batch endpoint is the only door, and it
checks the caller once for the whole batch instead of once per object.

**Challenge:** You are Alice (`alice-token`, org Acme). Read Globex's
`n_globex_1` by putting it in a batch next to one of your own notes. See
[`challenges/s12.md`](../challenges/s12.md).

---

## Scenario S13 — Token scope claim trusted as permission

**Tool:** `note_get_by_token_scope`  **Class:** CWE-639 / CWE-290 — a scope/aud claim trusted instead of the session  **Toggle:** `LAB_S13`

`note_get_by_token_scope` accepts an optional `scope` value standing in for a
token's `aud`/`scope` claim, and the vulnerable build uses it to choose whose
notes to return. The token proves *who* the caller is; it does not prove what
the caller may read. The fixed build ignores the claim and derives the scope
from the resolved session.

**Challenge:** You are Alice (`alice-token`, org Acme). Read Globex's notes by
presenting a scope claim of `org_globex`. See
[`challenges/s13.md`](../challenges/s13.md).
