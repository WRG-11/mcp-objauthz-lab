# Challenges

Four independent BOLA scenarios, each runnable in under 5 minutes.
Solve them in any order. Solutions are in [`../solutions/`](../solutions/).

| # | File | Pattern | Difficulty |
|---|---|---|---|
| S1 | [s1.md](s1.md) | Inconsistent authorization — the single outlier | Beginner |
| S2 | [s2.md](s2.md) | Client-supplied scope trusted as authorization | Beginner–Intermediate |
| S3 | [s3.md](s3.md) | List→get asymmetry — batch skips per-object check | Intermediate |
| S4 | [s4.md](s4.md) | Wildcard/sentinel value bypasses scope filter | Beginner |

## Ground rules

- Each challenge runs the server locally over stdio — no network, no third party.
- Use any MCP client (the included `poc/exploit.js`, Claude Desktop, Cursor, etc.).
- Do not modify server source; only change env vars and tool arguments.
- Each scenario is isolated: setting `LAB_S2=vuln` does not affect S1/S3/S4.

## How to interact with the server

The lab uses stdio transport. The easiest way to call tools interactively is
to wire it into an MCP host (Claude Desktop, Cursor) or write a small client
using `@modelcontextprotocol/sdk`. See `poc/exploit.js` for a working example.

Quick Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "objauthz-lab": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-objauthz-lab/src/server.js"],
      "env": { "LAB_MODE": "vuln", "LAB_S2": "vuln", "LAB_S3": "vuln", "LAB_S4": "vuln" }
    }
  }
}
```
