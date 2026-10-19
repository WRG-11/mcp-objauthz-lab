# mcp-audit

A [Claude Code skill](https://code.claude.com/docs/en/skills) that
audits the tool surface of an MCP server and writes one evidence-only report. It
scores every tool on how an agent would discover it, checks the surface for
inconsistent result shapes, names and errors, finds untested and unused tools,
and, on multi-tenant servers, runs this lab's object-level authorization rules
and hunt checklist. It reads; it never edits the audited code.

## Files

| File | What it is |
|---|---|
| [`SKILL.md`](SKILL.md) | The procedure the agent follows. |
| [`SEVERITY.md`](SEVERITY.md) | One row per finding type, with its default severity. |
| [`references/audit_template.md`](references/audit_template.md) | The report layout. |
| [`references/disclosure.md`](references/disclosure.md) | How to report findings on a server you do not maintain. |

## Install

Copy the folder into your personal skills directory, or into a project's
`.claude/skills/` to share it with everyone working on that project:

```bash
git clone --depth 1 https://github.com/WRG-11/mcp-objauthz-lab.git
mkdir -p ~/.claude/skills
cp -r mcp-objauthz-lab/skills/mcp-audit ~/.claude/skills/
```

On Windows PowerShell:

```powershell
git clone --depth 1 https://github.com/WRG-11/mcp-objauthz-lab.git
New-Item -ItemType Directory -Force "$HOME\.claude\skills" | Out-Null
Copy-Item -Recurse mcp-objauthz-lab\skills\mcp-audit "$HOME\.claude\skills\"
```

Then ask Claude Code to "audit this MCP server", or run `/mcp-audit`. The
authorization axis needs Semgrep and a checkout of this repository; the skill
tells the agent how to fetch both.

## Scope

The audit covers Python servers that register tools with a decorator (the MCP
Python SDK's high-level server, FastMCP) and TypeScript servers built on the
official SDK. On other stacks the procedure still applies, but the inventory
commands need adapting.

Run the authorization axis only against servers you own or are authorized to
test. On a server someone else maintains, read
[`references/disclosure.md`](references/disclosure.md) before reporting anything.
