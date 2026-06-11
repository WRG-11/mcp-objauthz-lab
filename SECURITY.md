# Security Policy

`mcp-objauthz-lab` is a **deliberately vulnerable, synthetic teaching lab** for
practising object-level authorization (BOLA / cross-tenant IDOR) review in Model
Context Protocol (MCP) servers. It ships a minimal two-tenant MCP server with one
**intentionally planted** object-level authorization flaw (a single outlier tool
handler) plus a hunt-checklist. All data is synthetic — no real users, secrets, or
production systems; the server is meant to be run locally.

## The planted flaw is intentional — do not report it

The lab's planted authorization bug is the **point** of the exercise (see the
README hunt-checklist and the `LAB_MODE` toggle). It is not a vulnerability.

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
