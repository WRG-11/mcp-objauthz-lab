# MCP Object-Authz Lab

> A small, self-hostable, **vulnerable-by-design** [MCP](https://modelcontextprotocol.io)
> server for learning how **object-level / cross-tenant authorization** bugs
> (BOLA / IDOR — [CWE-639](https://cwe.mitre.org/data/definitions/639.html),
> [CWE-862](https://cwe.mitre.org/data/definitions/862.html)) appear in Model
> Context Protocol tools, and how to hunt them.

It is a multi-tenant note server exposing nine MCP tools across **four independent
BOLA scenarios**. Each scenario is a different variant of the same bug class, toggled
by its own environment variable. Run them all at once or isolate one at a time.

## Why this lab exists

Most MCP security attention goes to **prompt injection** and tool-poisoning.
Object-level authorization is a quieter, different class, and the usual
prompt-injection test suites and scanners do **not** find it. When an MCP server
is multi-tenant, every tool that resolves an object from a **client-supplied id**
must verify the caller is allowed to touch *that* object. Miss the check on a
single tool and you have a cross-tenant read, write, or delete — regardless of
how good the prompt-injection defenses are. Catching it takes *reading the
authorization on each tool*, which is exactly the muscle this lab trains.

## Quickstart (< 5 minutes)

Requirements: **Node.js ≥ 20**.

```bash
npm install
npm run poc
```

Expected output (10/10 rows, all scenarios):

```
MCP object-level authorization lab — two-way gate (4 scenarios)

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

  Two-way gate: PASS (10/10 rows OK)
```

The PoC is a real MCP client. It spawns the server over stdio (**locally — no
network, no third party**) and runs a *two-way gate* per scenario: in the **vuln**
build the exploit succeeds; in the **fixed** build it is blocked and legitimate
same-org access still works (no false positive).

---

## Scenario S1 — Missing org-scope check (the original)

**Tool:** `note_delete`  
**Class:** CWE-639 / CWE-862 — object-level authorization  
**Toggle:** `LAB_MODE` / `LAB_S1`

Five of the six core note tools are correctly authorized: every one that
resolves an object by a client-supplied `id` calls `requireOrgAccess()` to
confirm the note belongs to the caller's org. `note_delete` does not (in vuln
mode) — **any caller can delete any org's note** by knowing or guessing its id.

**Challenge:** The server exposes `note_list`, `note_get`, `note_create`,
`note_update`, `note_delete`, `note_search`. Exactly one lets a caller in one
org delete another org's note. Which one, and what makes it different?

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

## How it is built

| File | Role |
|---|---|
| [`src/store.js`](src/store.js) | In-memory multi-tenant seed data: 3 orgs (*Acme/Alice*, *Globex/Bob*, *Initech/Carol*), 2 notes each (6 total). |
| [`src/auth.js`](src/auth.js) | `resolveSession(token)` → server-trusted `{ user, org }`; `requireOrgAccess(session, object)` — the object-level check. |
| [`src/tools.js`](src/tools.js) | Nine tools. Four planted-bug tools (one per scenario). |
| [`src/server.js`](src/server.js) | Stdio MCP server. Reads `LAB_MODE`/`LAB_S1..S4` env vars, passes a `modes` object to `registerTools`. |
| [`poc/exploit.js`](poc/exploit.js) | MCP client running the 10-row two-way gate across all 4 scenarios. |

**Identity model (deliberate simplification).** Each tool takes a bearer `token`
the server resolves to a fixed user and org. The caller never asserts its own org
— only presents a token. In a production MCP server this identity would come from
the transport / OAuth layer; the lab passes it per call so it stays a single
process and the authorization logic is explicit and easy to read.

---

## Environment variables

Each scenario is controlled by an independent env var (all default to `"vuln"`):

| Var | Controls | Vuln behaviour | Fixed behaviour |
|---|---|---|---|
| `LAB_MODE` / `LAB_S1` | S1 — `note_delete` | Cross-tenant delete succeeds | `requireOrgAccess()` blocks it |
| `LAB_S2` | S2 — `note_search` | `org_id` param overrides session scope | `org_id` ignored; session scope always used |
| `LAB_S3` | S3 — `note_batch_get` | All resolved notes returned regardless of org | Notes filtered to `session.orgId` |
| `LAB_S4` | S4 — `note_export` | `org_id="*"/"all"` dumps all tenants | `org_id` ignored; own org only |

Run all scenarios in their fixed state:

```bash
# Linux / macOS
LAB_S1=fixed LAB_S2=fixed LAB_S3=fixed LAB_S4=fixed npm start

# Windows PowerShell
$env:LAB_S1='fixed'; $env:LAB_S2='fixed'; $env:LAB_S3='fixed'; $env:LAB_S4='fixed'; npm start
```

Isolate one scenario (e.g. test only S2):

```bash
LAB_S2=vuln LAB_S1=fixed LAB_S3=fixed LAB_S4=fixed npm start
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
- [ ] **Role / token-type bypass.** An "admin" or "service" code path skips the
  per-object check.
- [ ] **List → get asymmetry (→ S3).** `list` only returns your org's objects, so
  ids feel "private" — but `get`/`batch-get` accept *any* id and the ids are
  guessable or enumerable.
- [ ] **Create/update accepting a foreign parent.** `create(parent_id=…)` accepts
  a parent the caller is not a member of, injecting an object into another tenant.

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

## License

[MIT](LICENSE).
