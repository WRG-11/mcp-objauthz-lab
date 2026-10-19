---
name: mcp-audit
description: Audit the tool surface of an MCP server for discoverability, return-shape and naming consistency, error handling, test coverage, decay, state handling and, on multi-tenant servers, object-level authorization. Produces one evidence-only Markdown report that ends in a short list of named fixes of an hour or less and a deferred backlog. Use when the user asks to "audit my MCP server", "score my MCP tools", "are my tool descriptions any good", "which of these tools is anyone using", "check this MCP server for BOLA", or invokes /mcp-audit. Works on Python servers that register tools with a decorator (the MCP Python SDK's high-level server, FastMCP) and on TypeScript servers that call registerTool. Read-only - it proposes fixes and never applies them.
---

# mcp-audit

A repeatable, read-only review of an MCP server's tool surface. The output is a
single Markdown report the maintainer can act on in one sitting: what each tool
is, how well an agent can tell when to call it, where the surface disagrees with
itself, what is untested or unused, and which few fixes to ship first.

The review scores tools on what can be checked in the source and the repository,
not on taste. Every finding cites a `finding_id` from [`SEVERITY.md`](SEVERITY.md),
so two audits of the same server can be compared row by row.

## Axes

Per tool:

1. Discoverability (1-5). Could an agent decide to call this tool from its
   description alone? 5 = trigger phrases, when-to-use guidance and the return
   shape; 1 = the description restates the function name.
2. Return shape. Does the tool use the surface's common result shape, or an
   idiom of its own? Count the idiom families across the whole surface.
3. Naming. One case convention, a shared domain prefix where the surface has
   families (`memory_*`, `issue_*`), one verb per operation.
4. Error handling. How each tool reports a failure: it raises, returns a structured error, or says nothing.
5. Test coverage. A test that goes through the MCP layer, a test of the
   underlying function only, a smoke call with no assertions, or nothing.
6. Decay. Mentioned in the CHANGELOG, in the README or docs, imported by any
   consumer, exercised by any test. A tool with none of the four is a decay
   candidate.

Per surface, when it applies:

7. State handling - servers that keep state across calls (files, a database,
   an in-memory store): atomic writes, a serialiser around load-mutate-save,
   persistence across a restart, state one tool can see that another wrote.
8. Object-level authorization - servers that serve more than one tenant,
   user or project: does every tool that resolves an object by id check that
   the caller may touch that object? See [Authorization axis](#authorization-axis).

## When to use it

Use it when:

- the user asks for an audit, a score, or "where should I focus" on an MCP server;
- a server has grown past roughly ten tools and nobody has reviewed the surface
  as a whole;
- a multi-tenant MCP server is about to be exposed to more than one customer.

Do not use it for:

- behavioural testing of individual tools - write tests;
- performance - profile instead;
- general code quality - linters and type checkers already do that.

## Procedure

### 0. Target check

Before scoring anything, record what is being audited:

- the repository, the package and its latest published version, and the commit
  being read;
- whether the package is still maintained (not archived, not moved, not
  deprecated). An archived target is worth auditing only to exercise the
  procedure; if the user wants findings someone will act on, say so and propose
  an active sibling instead.

### 1. Inventory

List every registered tool with its module and line.

```bash
# Python: decorator registration (@mcp.tool / @mcp.tool() / @server.tool(...))
grep -rnE "@[A-Za-z_]+\.tool\b" src/

# Python low-level server: tools come back from the list_tools handler
grep -rnE "@[A-Za-z_]+\.(list_tools|call_tool)\(" src/

# TypeScript SDK
grep -rnE "\.(registerTool|tool)\(" src/
```

In TypeScript the tool name is the first string argument, not the function name.
Resources (`resources/read`) and prompts are part of the surface too: list them,
even if only the tools are scored.

### 2. Discoverability

Read each description and its arguments, and score it against the rubric in
[`references/audit_template.md`](references/audit_template.md). Justify every
score below 5 in one sentence.

### 3. Consistency

Across all tools:

- Return shape: count each idiom (common envelope, raw dict, raw list or
  string, raise on error, error-by-key-presence). Report the distribution and
  name the outliers.
- Naming: mixed case conventions, missing family prefixes, verb collisions
  (`get_x` beside `fetch_y` for the same kind of read).
- Errors: per tool, raise versus structured result versus silent.

### 4. Tests and decay

For each tool, find the layer it is tested at, then run the four decay checks
mechanically: CHANGELOG, README/docs, consumers, tests. Do not skip a check
because the tool is "obviously used"; the point of the axis is that nobody
checked.

### 5. State handling (stateful servers only)

- Atomicity: do writes go through write-temp-then-rename or a transaction,
  or can a crash leave half a file?
- Concurrency: is there a lock around load, mutate, save? What happens when
  two mutation calls overlap?
- Persistence: does any test restart the server and read the state back?
- Leakage: can one tool observe what another wrote in a way the surface does
  not document?

Skip the axis for servers with no state. Map findings to the `STATE-*` rows.

### 6. Authorization axis

Run this axis on any server where one deployment serves more than one tenant,
user or project. Single-user local servers skip it and say so in the report.

1. Run the object-level authorization rules from
   [mcp-objauthz-lab](https://github.com/WRG-11/mcp-objauthz-lab) against the
   server's source. Record the lab commit the rules came from in the report.

   ```bash
   git clone --depth 1 https://github.com/WRG-11/mcp-objauthz-lab.git
   pip install -r mcp-objauthz-lab/detection/requirements.txt
   semgrep --config mcp-objauthz-lab/detection/semgrep/ <path-to-the-server-source>
   ```

   What the rules were measured to catch and miss is in
   [`detection/README.md`](https://github.com/WRG-11/mcp-objauthz-lab/blob/main/detection/README.md).
   A rule hit is a lead, not a finding: read the handler before recording it.
2. Walk the
   [hunt checklist](https://github.com/WRG-11/mcp-objauthz-lab/blob/main/docs/hunt-checklist.md)
   against every tool and resource handler that resolves an object by id. The
   rules miss shapes that sit behind configuration or a transport header; the
   checklist is how those get found.
3. Confirm each suspected finding the way the checklist describes: authenticate
   as one tenant, ask for another tenant's object, and see what comes back. Do
   this only against a server you own or are authorized to test.

Map confirmed findings to the `AUTHZ-*` rows in [`SEVERITY.md`](SEVERITY.md).

### 7. Priorities and decision gate

- Top priorities: at most five, each naming a tool and the shape of the fix,
  each an hour or less. Anything bigger goes to the backlog.
- Decision gate: total tools, average discoverability, share of tools on the
  common result shape, tools with MCP-layer tests; one or two fixes to ship this
  week; three to five backlog items; and a fate for every decay candidate
  (keep, soft-deprecate, remove).

[`references/audit_template.md`](references/audit_template.md) has the full
report layout.

## Small servers

Below ten tools, most of axes 1-4 are satisfied trivially and add noise. Run a
short version instead: target check, inventory, the `SEC-*` rows, test
coverage, state handling if it applies, the authorization axis if it applies,
and one to three priorities. Say in the report that the short version was used.

## Rules for the report

1. Score honestly in both directions. If the surface is well described, say
   so; "no discoverability problem" is a result. If a tool returns raw JSON and
   raises a bare exception, it scores low however carefully its docstring reads.
2. Name tools. "Improve descriptions" is not a priority. "Rewrite the
   `export_notes` description to say when to call it and what it returns" is.
   The maintainer should be able to grep every name the report uses.
3. The weekly pick must be shippable: one or two fixes, one pull request,
   under an hour.
4. Back history claims with history. A claim that a check was "added in one
   commit and silently removed in another" needs `git log -S "<symbol>" -- <path>`
   showing both, and `git branch -a --contains <commit>` showing the first commit
   was ever on the default branch. A commit that only exists on an unmerged
   branch was never removed from anything.
5. Check before calling a finding new. Before reporting a finding as
   unknown to the maintainer, search their tracker and history:

   ```bash
   gh issue list --repo <owner/repo> --state all --search "<keyword>"
   gh pr list    --repo <owner/repo> --state all --search "<keyword>"
   git log --all --grep="<keyword>"
   git log -S "<symbol>" -- <path>
   ```

   Record the queries and their result counts in the report. An existing issue
   changes how the finding is reported (see
   [`references/disclosure.md`](references/disclosure.md)).
6. Read-only. The audit writes one report. Fixes are the maintainer's.

## Output

Write the report to the audited repository, following its layout:
`docs/audit/MCP_AUDIT_<YYYY-MM-DD>.md`, or `docs/decisions/` in a repository
that keeps decision records. Do not create a new top-level folder for it.

## Auditing someone else's server

Findings about a server you do not maintain go to its maintainer before they go
anywhere public, through a channel that matches their severity.
[`references/disclosure.md`](references/disclosure.md) has the channel per
severity and the edge cases. Read it before opening any issue or pull request
upstream.

## What this is not

- not a linter, a type checker or a secret scanner;
- not a substitute for running the server's tests;
- not a judgement of whether a tool is worth having. It measures what can be
  checked in the repository; whether a tool earns its place is the maintainer's call.
