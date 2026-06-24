#!/usr/bin/env node
// Synthetic multi-tenant MCP server (stdio transport).
//
// Scenario env vars (each defaults to "vuln" if absent or any value other than "fixed"):
//
//   LAB_MODE / LAB_S1  — S1: note_delete missing org-scope check (the original bug)
//   LAB_S2             — S2: note_search trusts a caller-supplied org_id ("scope-as-param")
//   LAB_S3             — S3: note_batch_get skips per-object org check ("list→get asymmetry")
//   LAB_S4             — S4: note_export wildcard org_id="*" bypasses scope ("sentinel bypass")
//
// Each scenario is independent: set all to "fixed" to run the fully hardened server,
// or mix vuln/fixed to isolate one scenario at a time.
//
// Run directly with an MCP client (e.g. the included poc/exploit.js), or wire
// it into any MCP host. The protocol speaks over stdout/stdin — all human
// logging goes to stderr so it cannot corrupt the JSON-RPC stream.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createStore } from "./store.js";
import { registerTools } from "./tools.js";

const fixed = (v) => v === "fixed";

const modes = {
  // LAB_MODE is kept as the primary alias for S1 (backward-compat with existing PoC usage).
  s1: fixed(process.env.LAB_S1 ?? process.env.LAB_MODE) ? "fixed" : "vuln",
  s2: fixed(process.env.LAB_S2) ? "fixed" : "vuln",
  s3: fixed(process.env.LAB_S3) ? "fixed" : "vuln",
  s4: fixed(process.env.LAB_S4) ? "fixed" : "vuln",
};

const server = new McpServer({
  name: "mcp-objauthz-lab",
  version: "2.0.0",
});

const store = createStore();
registerTools(server, store, modes);

const transport = new StdioServerTransport();
await server.connect(transport);

// stderr only — never stdout (that is the protocol channel).
console.error(
  `[mcp-objauthz-lab] up  S1=${modes.s1}  S2=${modes.s2}  S3=${modes.s3}  S4=${modes.s4}`,
);
