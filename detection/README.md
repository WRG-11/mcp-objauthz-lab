# Detection rules — object-level authz in MCP tool code

Static-analysis complement to the hands-on [`challenges/`](../challenges/README.md).
The challenges teach a human to *find* the object-level authorization bug class
(BOLA/IDOR, CWE-639/862/863) by reading tool handlers; these rules teach a
scanner to flag the same patterns automatically in **your own** MCP server
code, not just this lab's.

## What's here

[`semgrep/mcp-object-authz.yml`](semgrep/mcp-object-authz.yml) — 14
[Semgrep](https://semgrep.dev) rules covering the shapes from the eight lab
scenarios. Nine of the fourteen run against **Python as well as
JavaScript/TypeScript**: three shared rules declare both, and six `-py`
siblings carry the shapes whose JavaScript spelling cannot parse as Python
(`=>` arrows, object literals, `registerTool`/`registerResource` callbacks):

| Rule id | Scenario(s) | Pattern |
|---|---|---|
| `mcp-missing-object-authz-check` | S1 | object resolved by client id, mutated/returned with no `require*Access`/`check*Access`/`assert*Owner` call in between |
| `mcp-client-supplied-scope-overrides-session` | S2 | `org_id`/`tenant_id`/`project_id`/`user_id`/`owner_id` argument used as a fallback/override for the session's own scope |
| `mcp-wildcard-sentinel-scope-bypass` | S4 | a `"*"`/`"all"` sentinel value bypasses scope filtering with no role check nearby |
| `mcp-batch-resolve-missing-per-item-scope-filter` | S3 | a batch of client-supplied ids is resolved with no `.filter(...)` back to the caller's own scope |
| `mcp-admin-named-tool-missing-role-check` | S5 | a tool named `*admin*` never calls a role-check function in its handler |
| `mcp-client-supplied-scope-overrides-session-py-ternary` | S2 (Python) | Python's `x if x else y` spelling of the same override — a separate rule because a multi-language rule needs every pattern valid in *every* declared language |
| `mcp-unscoped-query-object-fetch` | S7 | a repository fetch (`findOneBy` / `findOne({ where })` / `delete`) whose filter carries an `id` but **no** tenant key. **WARNING, not ERROR** — a single call can't prove the entity is tenant-scoped, so it flags the shape for review |
| `mcp-write-parent-from-client-argument` | S6 | a `create`/`save` call whose parent or tenant key comes from a caller-supplied argument instead of the session, with no membership check on it. **WARNING, not ERROR** — bound straight from an argument this is a true positive, bound through a local the variable's origin decides and one call site cannot show it |
| `mcp-batch-resolve-missing-per-item-scope-filter-py` | S3 (Python) | the same list→get asymmetry in list-comprehension spelling (`[store.get_note(i) for i in ids]`) |
| `mcp-admin-named-tool-missing-role-check-py` | S5 (Python) | an `@mcp.tool()`-decorated function named `*admin*` whose body never calls a role check |
| `mcp-unscoped-query-object-fetch-py` | S7 (Python) | SQLAlchemy spellings of the unscoped fetch: `filter_by(id=...)` with no tenant kwarg, and a primary-key `session.get(Model, pk)`. **WARNING**, same honesty as its JS sibling |
| `mcp-write-parent-from-client-argument-py` | S6 (Python) | the kwargs spelling of the foreign-parent create/save. **WARNING**, same honesty as its JS sibling |
| `mcp-resource-uri-variable-used-as-scope` | S8 | an MCP resource read callback (`resources/read`, not `tools/call`) binds a tenant/scope key straight from a URI template variable instead of the session |
| `mcp-resource-uri-variable-used-as-scope-py` | S8 (Python) | the FastMCP `@mcp.resource(...)`-decorated spelling: the template variable is a function parameter, not a destructured object |
| `mcp-missing-object-authz-check-go` | S1 (Go) | object resolved by `$STORE.$GETMETHOD($ID)`, mutated with no `Require*Access`/`Check*Access`/`Assert*Owner` call (exported and unexported spelling) in between |
| `mcp-client-supplied-scope-overrides-session-go` | S2 (Go) | Go's zero-value-fallback spelling of the override (`scope := args.OrgID; if scope == "" { scope = session.OrgID }`) — Go has no `||`/`??`/ternary, so the JS/PY override shape doesn't port directly |
| `mcp-unscoped-query-object-fetch-go` | S7 (Go) | the struct/ORM primary-key lookup idiom, `$DB.First(&$X, $ID)`, with no tenant key bound into the same query. **WARNING**, same honesty as its JS/PY siblings — and a narrower one: a raw-SQL-string lookup is a Go-specific blind spot this rule does not cover (see below) |
| `mcp-missing-object-authz-check-rust` | S1 (Rust) | `let`-bound fetch/mutate sequence (`let obj = store.get(&id); ... store.delete(&obj.id)`) with no `require_*`/`check_*`/`assert_*` call in between (snake_case guard names) |
| `mcp-client-supplied-scope-overrides-session-rust` | S2 (Rust) | a client-destructured scope field (`org_id` from `Parameters<T>`) reaching the store call in place of the session's own; the anchored name regex leaves a `session.org_id` field access silent |
| `mcp-admin-named-tool-missing-role-check-rust` | S5 (Rust) | an admin-named `#[tool]` async fn whose body never calls `require_admin_role`/`check_admin_role`/`assert_admin_role` — naming is documentation, not enforcement |

### Go pack

[`semgrep/mcp-object-authz-go.yml`](semgrep/mcp-object-authz-go.yml) covers
Go MCP servers built on
[`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk),
in its own file — same reason the Python siblings are separate rules rather
than patterns bolted onto the shared ones: Go's syntax (no `||`/ternary,
PascalCase/camelCase casing, `:=` short declarations) doesn't parse as
JavaScript or Python, and a rule with an unparseable pattern silently stops
matching in *every* language it declares.

Three of the seven scenarios are covered (S1, S2, S7); the honest gap is S7
itself — Go's most common unscoped-fetch shape is a raw SQL string
(`db.QueryRow("SELECT ... WHERE id = $1", id)`), and a tenant key's absence
inside a string literal isn't something Semgrep can reliably see. The rule
locks onto the statically matchable struct/ORM idiom (`db.First(&x, id)`)
instead of guessing at string contents.

### Rust pack

[`semgrep/mcp-object-authz-rust.yml`](semgrep/mcp-object-authz-rust.yml) covers
Rust MCP servers built on the [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk)
crate, in its own file for the same reason as the Go pack. Semgrep's Rust
support was verified to parse the real `rmcp` handler idiom
(`Parameters(T { .. }): Parameters<T>` destructuring on a `#[tool_router]`
impl) with zero parse errors before the rules were written.

Three scenarios are covered (S1, S2, S5). The rules are pattern-based, matching
the house style (no existing rule uses `mode: taint`); the S2 rule keys on the
scope field's *name*, so a session-derived local that is renamed to `org_id`
is a documented, deliberate limitation rather than a miss — taint mode resolves
it and was verified to do so, but is kept out to match the existing rules.

## Run it

```bash
pip install semgrep
semgrep --config detection/semgrep/ <path-to-your-mcp-server>
```

Or as a GitHub Action, no local install needed — add this step to your own
MCP server's CI (requires `security-events: write` for the SARIF upload):

```yaml
permissions:
  security-events: write

steps:
  - uses: WRG-11/mcp-objauthz-lab@main
    with:
      path: src/   # your MCP server source
```

The action installs semgrep, runs this same rule-set producing SARIF,
uploads it to your repo's Security tab (set `upload-sarif: false` to skip),
then fails the job if any finding is present. See
[`action.yml`](../action.yml) at the repo root.

## Honest results — this is not a magic bullet

Two ways this was validated, with different outcomes, both worth knowing
before you rely on it:

**1. Isolated fixture code** ([`semgrep/fixtures/`](semgrep/fixtures/)) — one
minimal vulnerable snippet and one fixed snippet per rule. **14/14 rules fire
on the vulnerable snippet and stay silent on the fixed one.** This is the
correctness bar every rule was iterated against.

**2. This lab's own `src/tools.js`** — the *real* source, where vuln/fixed
are the same code gated by a runtime `LAB_MODE` toggle (`if (modes.s1 ===
"fixed") requireOrgAccess(...)`), not two separate files. Running the
ruleset against it: **7 of 9 scenarios flagged (S2, S3, S4, S6, S7, S8, S9).
S1 and S5 are missed.**

S9 has no dedicated rule. Measured before deciding that: `mcp-missing-
object-authz-check` (S1's rule) already fires on `note_share_redeem`'s vuln
branch, because the handler happens to carry the exact shape that rule
targets — `$SESSION = resolveSession(...); ...; $OBJ = store.getNote($ID);
...; return ok($OBJ);` with no guard call in between. A probe file (three
functions: the vuln shape with a local assignment, the fixed shape, and an
inline assignment-free spelling of the vuln shape) confirmed it fires on the
first and stays silent on the other two. That last case is the caveat worth
keeping: the rule catches `const note = store.getNote(id); ...; return
ok(note)`, but **not** the same defect spelled inline as
`return ok(store.getNote(id))` with no local variable — `mcp-missing-object-
authz-check` was never anchored on an assignment by design, it just happens
that both S1 and S9's tools.js code write it that way.

Why S1/S5 are missed *there* — and why that says nothing about the rules on
real code. Both rules work by checking that no authorization call *textually
appears* between the object lookup and the sink. In `tools.js` the
`requireOrgAccess()` / `requireAdminRole()` call **does** appear in the
function body — it's just gated behind an `if (modes.sN === "fixed")`
runtime condition the static rule cannot evaluate. Measured 2026-08-23 on
production-shaped probe files with the toggle stripped out and the guard
simply absent: both rules fire exactly as they should (`deleteNoteVuln` →
finding; the guarded sibling → silent). The earlier published framing that
this was "a real limitation, not a lab artifact" was wrong in the direction
that matters: it implied the rules miss real-world S1/S5 bugs. They do not —
they only go quiet where a guard is *written but conditional*, which is this
lab's own scaffolding shape.

The decision, taken deliberately: **the rules do not see through toggles.**
Treating a conditionally-present guard as absent would flag code like

```javascript
if (config.strictAuthz) requireAccess(session, obj);   // legitimate
await store.deleteObject(obj.id);
```

which is a real production pattern and textually indistinguishable from the
lab's toggle at this rule's matching depth — measured, not guessed. A gate
that wide produces the false positives that get a rule switched off, and
narrowing it to this lab's literal `"fixed"` spelling would tune the detector
to its own lab. [`toggle-blindness.js`](semgrep/fixtures/toggle-blindness.js)
pins all of this as fixtures: for S1 and S5 each, a toggle-free vulnerable
handler (fires), the lab's toggle-guarded spelling (silent, on purpose), and
an unconditionally-guarded handler (silent).

S2/S3/S4/S6 don't have this problem because their bug is about an
*unconditional* fallback/sentinel/missing-filter shape, not a conditionally-
present check call — those rules match the runtime toggle correctly.

## A real-world referent — and what it caught the rules missing

This lab is vulnerable-by-design, so the fair question is whether the bug class
shows up in software people actually deploy. It does, with a CVE number:

**[CVE-2026-9135](https://nvd.nist.gov/vuln/detail/CVE-2026-9135)** (IBM
Langflow OSS, CVSS 9.9). Alongside a code-injection flaw, NVD's description
records that the attack *"can be escalated through cross-tenant flow
manipulation via the agentic MCP `update_flow_component_field` tool, which
accepts attacker-controlled `user_id` parameters, enabling attackers to inject
malicious code into victim users' flows."*

A caller-supplied identity argument selecting whose data a tool operates on is
scenario **S2** exactly — the same shape as the lab's `org_id || session.orgId`,
one word different.

**And the rule did not catch it.** `mcp-client-supplied-scope-overrides-session`
enumerated tenant-scope parameter names — `org_id`, `tenant_id`, `project_id`,
`account_id`, `workspace_id` — and `user_id` was not among them. Because
`patterns` is an AND, a failing `metavariable-regex` means the rule cannot fire
at all, however well the code shape matches. Measured before the fix: a probe
carrying `user_id ||`, `user_id ??` and `owner_id ||` produced **zero**
findings, while the `org_id` control in the same file fired.

`user_id`/`owner_id` (and their camelCase forms) are now in the list, with a
vulnerable + fixed fixture pair for each. Two things worth taking from this
beyond the one-line fix:

- An allow/deny list of *names* is a guess about what the next codebase will
  call the thing. It fails silently and completely — no partial match, no
  warning, just a clean scan.
- The first public CVE of this class used the spelling the rule did not have.
  If you adapt these rules, start by auditing that regex against your own
  parameter vocabulary rather than trusting the defaults.

CVE-2026-9135 is Python. When this rule missed `user_id` the ruleset could not
have scanned Langflow's source at all; since 3.2.0 the S2 rules — including
this one — declare Python, so a current scan of Langflow-shaped code reaches
the same spelling (`user_id or session.user_id`) that fires in JavaScript.
The CVE is cited as evidence that the *shape* occurs in production MCP
tooling, not as a claim about any past scan.

## Why this exists (vs. just using the hands-on lab)

The challenges train a human. This is the automatable half: something a
CI pipeline or a pre-commit hook can run on a real MCP server's source
without a human reading every tool handler by hand. Neither replaces the
other — a scanner with the S1/S5 blind spot above still needs the human
"read every tool that resolves an object by id" habit the hunt checklist
teaches.

## Related

[WRG-11/wrg-sigma-rules](https://github.com/WRG-11/wrg-sigma-rules) —
detection rules for a different layer (runtime/log-based Sigma rules for
security telemetry) rather than source-code static analysis. Different
artifact type, same author, same "detect the bug class, not just teach it"
motivation.
