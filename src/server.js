#!/usr/bin/env node
// Synthetic multi-tenant MCP server (stdio transport).
//
//   LAB_MODE=vuln  (default)  -> note_delete is missing its org-scope check
//   LAB_MODE=fixed            -> note_delete is authorized like its siblings
//
// Run directly with an MCP client (e.g. the included poc/exploit.js), or wire
// it into any MCP host. The protocol speaks over stdout/stdin — all human
// logging goes to stderr so it cannot corrupt the JSON-RPC stream.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createStore } from "./store.js";
import { registerTools } from "./tools.js";

const mode = process.env.LAB_MODE === "fixed" ? "fixed" : "vuln";

const server = new McpServer({
  name: "mcp-objauthz-lab",
  version: "1.0.0",
});

const store = createStore();
registerTools(server, store, mode);

const transport = new StdioServerTransport();
await server.connect(transport);

// stderr only — never stdout (that is the protocol channel).
console.error(`[mcp-objauthz-lab] up (LAB_MODE=${mode})`);
