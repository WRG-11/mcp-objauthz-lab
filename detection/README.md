# Detection rules — object-level authz in MCP tool code

Static-analysis complement to the hands-on [`challenges/`](../challenges/README.md).
The challenges teach a human to *find* the object-level authorization bug class
(BOLA/IDOR, CWE-639/862/863) by reading tool handlers; these rules teach a
scanner to flag the same patterns automatically in **your own** MCP server
code, not just this lab's.

## What's here

[`semgrep/mcp-object-authz.yml`](semgrep/mcp-object-authz.yml) — 5
[Semgrep](https://semgrep.dev) rules, one per shape from the six lab
scenarios (S2 and S6 share a rule — same code shape, different tool):

| Rule id | Scenario(s) | Pattern |
|---|---|---|
| `mcp-missing-object-authz-check` | S1 | object resolved by client id, mutated/returned with no `require*Access`/`check*Access`/`assert*Owner` call in between |
| `mcp-client-supplied-scope-overrides-session` | S2, S6 | `org_id`/`tenant_id`/`project_id` argument used as a fallback/override for the session's own scope |
| `mcp-wildcard-sentinel-scope-bypass` | S4 | a `"*"`/`"all"` sentinel value bypasses scope filtering with no role check nearby |
| `mcp-batch-resolve-missing-per-item-scope-filter` | S3 | a batch of client-supplied ids is resolved with no `.filter(...)` back to the caller's own scope |
| `mcp-admin-named-tool-missing-role-check` | S5 | a tool named `*admin*` never calls a role-check function in its handler |

## Run it

```bash
pip install semgrep
semgrep --config detection/semgrep/mcp-object-authz.yml <path-to-your-mcp-server>
```

## Honest results — this is not a magic bullet

Two ways this was validated, with different outcomes, both worth knowing
before you rely on it:

**1. Isolated fixture code** ([`semgrep/fixtures/`](semgrep/fixtures/)) — one
minimal vulnerable snippet and one fixed snippet per rule. **5/5 rules fire
on the vulnerable snippet and stay silent on the fixed one.** This is the
correctness bar every rule was iterated against.

**2. This lab's own `src/tools.js`** — the *real* source, where vuln/fixed
are the same code gated by a runtime `LAB_MODE` toggle (`if (modes.s1 ===
"fixed") requireOrgAccess(...)`), not two separate files. Running the
ruleset against it: **4 of 6 scenarios flagged (S2, S3, S4, S6). S1 and S5
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
