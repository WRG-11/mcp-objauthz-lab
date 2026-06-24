# LinkedIn Post Draft (A gözden geçirir ve gönderir)

---

I've been thinking about how MCP security education works in practice.

Prompt injection gets most of the attention. But there's a quieter bug class that
matters just as much for multi-tenant MCP servers: **object-level authorization**
— the server knows who you are, but forgets to check whether you're allowed to
touch *that specific object*.

We built a small lab to make these patterns hands-on and runnable:

**mcp-objauthz-lab** — a vulnerable-by-design MCP note server with 4 independent
BOLA scenarios, each toggled by an env var:

- S1 — One tool is missing a single line compared to its siblings. Which one?
- S2 — A "scope" parameter is documented as admin-only. What happens if you pass it?
- S3 — The list endpoint is safely scoped. The batch-get endpoint is not.
- S4 — There's a magic value in the tool description. It works.

Each scenario has a runnable exploit and a two-way verification gate (vuln
exploits → fixed blocks → same-org still works). Node.js ≥ 20, `npm install`,
`npm run poc`.

→ github.com/WRG-11/mcp-objauthz-lab

The hunt checklist in the README covers 8 patterns total. We've built 4. If
you've seen different BOLA variants in the wild (or want to contribute a
scenario), open an issue.

#mcp #appsec #authorization #bola #idor #llmsecurity

---

*Not: em-dash kullanımını minimize et (slop-lint uyarısı). A gönderir.*
