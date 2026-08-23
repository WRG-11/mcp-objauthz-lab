# Detection rules — object-level authz in MCP tool code

Static-analysis complement to the hands-on [`challenges/`](../challenges/README.md).
The challenges teach a human to *find* the object-level authorization bug class
(BOLA/IDOR, CWE-639/862/863) by reading tool handlers; these rules teach a
scanner to flag the same patterns automatically in **your own** MCP server
code, not just this lab's.

## What's here

[`semgrep/mcp-object-authz.yml`](semgrep/mcp-object-authz.yml) — 8
[Semgrep](https://semgrep.dev) rules covering the shapes from the seven lab
scenarios (S2 and S6 share a rule — same code shape, different tool):

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

## Run it

```bash
pip install semgrep
semgrep --config detection/semgrep/mcp-object-authz.yml <path-to-your-mcp-server>
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
minimal vulnerable snippet and one fixed snippet per rule. **7/7 rules fire
on the vulnerable snippet and stay silent on the fixed one.** This is the
correctness bar every rule was iterated against.

**2. This lab's own `src/tools.js`** — the *real* source, where vuln/fixed
are the same code gated by a runtime `LAB_MODE` toggle (`if (modes.s1 ===
"fixed") requireOrgAccess(...)`), not two separate files. Running the
ruleset against it: **5 of 7 scenarios flagged (S2, S3, S4, S6, S7). S1 and S5
are missed.**

Why S1/S5 are missed: both rules work by checking that no authorization
call *textually appears* between the object lookup and the sink. In
`tools.js` the `requireOrgAccess()` / `requireAdminRole()` call **does**
appear in the function body — it's just gated behind an `if
(modes.sN === "fixed")` runtime condition the static rule can't evaluate.
A purely static, non-dataflow tool cannot distinguish "the check always
runs" from "the check runs only if a flag says so" without control-flow
analysis. **This is a real limitation, not just a lab artifact** — any
codebase with a feature-flagged or config-gated authorization check has the
same blind spot for this rule shape. Treat a clean scan as "no *obvious*
missing-check pattern found," not "no S1/S5-class bug exists."

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

CVE-2026-9135 is Python; these rules are JavaScript/TypeScript, so they could
not have scanned Langflow itself. The CVE is cited as evidence that the *shape*
occurs in production MCP tooling, not as something this ruleset would have
found in place.

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
