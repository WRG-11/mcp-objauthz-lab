# MCP Object-Authz Lab

> A small, self-hostable, **vulnerable-by-design** [MCP](https://modelcontextprotocol.io)
> server for learning how **object-level / cross-tenant authorization** bugs
> (BOLA / IDOR — [CWE-639](https://cwe.mitre.org/data/definitions/639.html),
> [CWE-862](https://cwe.mitre.org/data/definitions/862.html)) appear in Model
> Context Protocol tools, and how to hunt them.

It is a multi-tenant note server exposing six MCP tools. Five are correctly
authorized. **Exactly one** is missing its access check, so a caller in one
organization can reach another organization's data through it. The bug is
subtle on purpose: the broken tool looks just like its siblings — it is missing
a single line. Find it, exploit it locally, then flip one switch to see it
fixed.

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

Expected output:

```
MCP object-level authorization lab — two-way gate

  BUILD  ACTION                                 OUTCOME  EXPECT   OK
  vuln   note_get   cross-tenant (Bob → Acme)   DENIED   DENIED   ✓
  vuln   note_delete cross-tenant (Bob → Acme)  DELETED  DELETED  ✓
  fixed  note_delete cross-tenant (Bob → Acme)  DENIED   DENIED   ✓
  fixed  note_delete same-tenant (Bob → Globex) DELETED  DELETED  ✓

  Two-way gate: PASS (vuln exploits, fix blocks the cross-tenant delete and still allows the same-tenant one).
```

The PoC is a real MCP client. It spawns the server over stdio (**locally — no
network, no third party**), authenticates as **Bob** (org *Globex*), and tries
to reach a note owned by **Acme**. It runs a *two-way gate*:

- in the **vuln** build the cross-tenant delete **succeeds** (the exploit), while
  the *correctly-scoped* `note_get` is still denied — proving the server has a
  **single** broken tool, not a globally missing check;
- in the **fixed** build the same cross-tenant delete is **blocked**, and Bob
  deleting his *own* org's note still **works** — proving the fix does not
  over-block (no false positive).

## The challenge

Before you read `src/`: the server exposes six note tools —
`note_list`, `note_get`, `note_create`, `note_update`, `note_delete`,
`note_search`. **Exactly one** lets a caller in one org affect another org's
note. Which one, and what makes it different from the others?

<details>
<summary>Hint</summary>

Three tools take a client-supplied `id` (`note_get`, `note_update`,
`note_delete`). Two of them check that the resolved object belongs to your org.
One does not.
</details>

<details>
<summary>Answer</summary>

`note_delete`. It resolves the note from the client-supplied `id` exactly like
`note_get` and `note_update`, but (in `LAB_MODE=vuln`) it never calls
`requireOrgAccess(session, note)`. The fix is that one line — the same check its
siblings already perform. See the comment block in
[`src/tools.js`](src/tools.js) above `note_delete`.
</details>

## How it is built

| File | Role |
|---|---|
| [`src/store.js`](src/store.js) | In-memory multi-tenant seed data: orgs *Acme* (Alice) and *Globex* (Bob), a few notes each. |
| [`src/auth.js`](src/auth.js) | `resolveSession(token)` → server-trusted `{ user, org }`; `requireOrgAccess(session, object)` — the object-level check. |
| [`src/tools.js`](src/tools.js) | The six tools. `note_delete` is the planted outlier. |
| [`src/server.js`](src/server.js) | Stdio MCP server. Reads `LAB_MODE` (`vuln` default / `fixed`). |
| [`poc/exploit.js`](poc/exploit.js) | MCP client running the two-way gate above. |

**Identity model (a deliberate simplification).** Each tool takes a bearer
`token` that the server resolves to a fixed user and org. The caller never
asserts its own org — only presents a token. In a production MCP server this
identity would come from the transport / OAuth layer rather than a per-call
argument; the lab passes it per call so it stays a single process and the
authorization logic is explicit and easy to read.

## Vulnerable vs fixed

One environment variable toggles the planted bug, so you can run either build in
your own MCP host:

```bash
# vulnerable (default)
npm start
# or: LAB_MODE=vuln npm start

# fixed
LAB_MODE=fixed npm start
```

On Windows PowerShell:

```powershell
$env:LAB_MODE = 'fixed'; npm start
```

The *only* difference between the two builds is the single line marked
`// <-- THE FIX` in `note_delete`.

## Hunt checklist — object-level authorization in MCP

Use this when auditing a real multi-tenant MCP server (one you own or are
authorized to test). The bug class is "the server authenticates *who you are*
but forgets to check *whether you may touch this object*":

- [ ] **Client-supplied scope trusted as authorization.** A tool takes an
  `org_id` / `project_id` / `tenant_id` / `account_id` argument and uses it to
  *scope the query* instead of *checking it against the caller's membership*.
- [ ] **Membership check decoupled from object resolution.** The tool verifies
  the caller belongs to some org/project, but loads the object by a *different*
  id (the object's own `id`) without confirming the object lives under that
  membership. (Authorize the object you are about to return/mutate — not a
  parameter next to it.)
- [ ] **Inconsistent authorization — the single outlier.** Most object tools
  check; one or two do not. Read **every** tool that resolves an object by id,
  not a sample. The forgotten one is usually a less-glamorous verb (`delete`,
  `update`, `archive`, `export`, a "cover"/"make-default" side action).
- [ ] **Reads guarded, mutations not.** `get`/`list` are scoped but
  `update`/`delete`/`transfer` slipped through — or vice-versa.
- [ ] **Wildcard / sentinel short-circuit.** A special value
  (`'all'`, `'*'`, empty, `0`, `null`) skips the scope filter entirely.
- [ ] **Role / token-type bypass.** An "internal", "service", "admin", or
  alternate-JWT-type code path skips the per-object check.
- [ ] **List → get asymmetry.** `list` only returns your org's objects, so ids
  feel "private" — but `get`/`delete` accept *any* id and the ids are guessable
  or enumerable.
- [ ] **Create/update accepting a foreign parent.** `create(parent_id=…)` or a
  re-parent on `update` accepts a parent the caller is not a member of,
  injecting an object into another tenant.

The exploit primitive is always the same: authenticate as tenant **B**, call the
suspect tool with an object id that belongs to tenant **A**, and see whether you
get **A**'s data (or mutate it). Confirm a fix the same way the PoC here does —
**two-way**: the cross-tenant call must be blocked *and* the legitimate
same-tenant call must still succeed.

## Safety / scope

- **Vulnerable by design.** Do **not** deploy this on a reachable network or use
  it as a starting point for real code. Run it locally for learning only.
- **Synthetic.** All orgs, users, notes, and tokens are made up. There is no
  real data, no real target, and the PoC never makes a network request — it only
  spawns the local server process.

## License

[MIT](LICENSE).
