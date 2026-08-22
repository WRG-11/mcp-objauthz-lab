# Security Policy

`mcp-objauthz-lab` is a **deliberately vulnerable, synthetic teaching lab** for
practising object-level authorization (BOLA / cross-tenant IDOR) review in Model
Context Protocol (MCP) servers. It ships a minimal multi-tenant MCP server with
**seven intentionally planted** object-level authorization flaws (scenarios S1-S7,
each an independent tool handler) plus a hunt-checklist. All data is synthetic —
no real users, secrets, or production systems; the server is meant to be run
locally.

## The planted flaws are intentional — do not report them

All seven planted authorization bugs are the **point** of the exercise (see the
README hunt-checklist and the `LAB_MODE` / `LAB_S1`-`LAB_S7` toggles). They are
not vulnerabilities. Note that every toggle **defaults to `vuln`**, so a server
started with no environment set has all seven live — that is intended.

## Reporting an *unintended* issue

A problem **beyond** the planted flaw — harness/tooling, build pipeline, a
dependency, or a way the lab could harm someone who runs it — report privately:

- **GitHub private vulnerability reporting** (preferred) — the **Report a
  vulnerability** button on this repo's **Security** tab.
- **Email** — `winstonrgsocial@gmail.com`

Please don't open a public issue before it's addressed. We respond within a few days.

## Scope

**In scope:** this repo's lab server, harness/tooling, build/release pipeline.
**Out of scope:** the intentionally-planted lab flaw, and any third-party MCP server
you test against.
