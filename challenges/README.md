# Challenges

Thirteen independent BOLA scenarios, each runnable in under 5 minutes.
Solve them in any order. Solutions are in [`../solutions/`](../solutions/).

| # | File | Pattern | Difficulty |
|---|---|---|---|
| S1 | [s1.md](s1.md) | Inconsistent authorization — the single outlier | Beginner |
| S2 | [s2.md](s2.md) | Client-supplied scope trusted as authorization | Beginner–Intermediate |
| S3 | [s3.md](s3.md) | List→get asymmetry — batch skips per-object check | Intermediate |
| S4 | [s4.md](s4.md) | Wildcard/sentinel value bypasses scope filter | Beginner |
| S5 | [s5.md](s5.md) | Role/token-type bypass — admin-named tool, no role check | Beginner–Intermediate |
| S6 | [s6.md](s6.md) | Foreign-parent injection — create trusts a caller-supplied org | Intermediate |
| S7 | [s7.md](s7.md) | Unscoped query — tenant key omitted from the filter | Intermediate |
| S8 | [s8.md](s8.md) | Resource-URI-as-scope — the resources/read surface | Intermediate |
| S9 | [s9.md](s9.md) | Authz-from-client-round-tripped-value — an editable share grant | Intermediate |
| S10 | [s10.md](s10.md) | Forwarded-header-as-scope — a trusted request header (HTTP transport) | Intermediate |
| S11 | [s11.md](s11.md) | X-Forwarded-For quota bypass — a trusted request header for rate limiting (HTTP transport) | Intermediate |
| S12 | [s12.md](s12.md) | Batch/bulk endpoint BOLA — multi-object endpoint without per-item tenant filter | Intermediate |
| S13 | [s13.md](s13.md) | JWT/token scope confusion — token's scope/aud claim vs actual permissions mismatch | Intermediate |

## Ground rules

- Each challenge runs the server locally over stdio — no network, no third party.
- Use any MCP client (the included `poc/exploit.js`, Claude Desktop, Cursor, etc.).
- Do not modify server source; only change env vars and tool/resource arguments.
- The toggles are independent — setting `LAB_S2` never changes S1/S3/S4/S5/S6/S7/S8/S9/S10/S11/S12/S13.
- **But every scenario defaults to `vuln` when its variable is unset**, so
  "independent" is not "off". Each challenge's Setup block therefore pins the
  other twelve to `fixed`. Run the bare `LAB_S2=vuln node src/server.js` and all
  thirteen bugs are live at once: as an ordinary user you can reach another org's
  data through thirteen different tools/resources, which makes S1 ("find the one
  tool") unanswerable and turns the rest into guess-which-one-was-meant.

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
      "env": { "LAB_MODE": "vuln", "LAB_S2": "vuln", "LAB_S3": "vuln", "LAB_S4": "vuln", "LAB_S5": "vuln", "LAB_S6": "vuln", "LAB_S7": "vuln", "LAB_S8": "vuln", "LAB_S9": "vuln", "LAB_S10": "vuln", "LAB_S11": "vuln" }
    }
  }
}
```
