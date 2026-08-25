// Streamable-HTTP entry point for the lab — the transport S10 and S11 need.
//
 // `server.js` (stdio) is the default for local use. This variant runs the SAME
 // tools and store over the MCP streamable-HTTP transport, so a tool call
 // carries the underlying HTTP request's headers in `extra.requestInfo.headers`.
 // That is the surface S10 (note_get_scoped, forwarded-header-as-scope) and
 // S11 (note_create_limited, XFF quota bypass) need; over stdio there is no
 // requestInfo and both silently fall back to the session.
 //
 // Run:  node src/http-server.js            (PORT defaults to 3010)
 // Toggle S10/S11 (or any scenario) the same way as the stdio server: LAB_S10=fixed LAB_S11=fixed.
 //
 // This is a deliberately minimal, single-session server for the lab/PoC — it is
 // NOT a production HTTP-MCP deployment (no auth on the endpoint, one shared
 // session). The teaching content is the header-trust bug inside the tool, not
 // the HTTP plumbing around it.

import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createStore } from "./store.js";
import { registerTools } from "./tools.js";

const fixed = (v) => v === "fixed" || v === "1" || v === "true";

const modes = {
  s1: fixed(process.env.LAB_S1 ?? process.env.LAB_MODE) ? "fixed" : "vuln",
  s2: fixed(process.env.LAB_S2) ? "fixed" : "vuln",
  s3: fixed(process.env.LAB_S3) ? "fixed" : "vuln",
  s4: fixed(process.env.LAB_S4) ? "fixed" : "vuln",
  s5: fixed(process.env.LAB_S5) ? "fixed" : "vuln",
  s6: fixed(process.env.LAB_S6) ? "fixed" : "vuln",
  s7: fixed(process.env.LAB_S7) ? "fixed" : "vuln",
  s8: fixed(process.env.LAB_S8) ? "fixed" : "vuln",
  s9: fixed(process.env.LAB_S9) ? "fixed" : "vuln",
  s10: fixed(process.env.LAB_S10) ? "fixed" : "vuln",
  s11: fixed(process.env.LAB_S11) ? "fixed" : "vuln",
  s12: fixed(process.env.LAB_S12) ? "fixed" : "vuln",
  s13: fixed(process.env.LAB_S13) ? "fixed" : "vuln",
};

const HERE = dirname(fileURLToPath(import.meta.url));
const { version } = JSON.parse(
  readFileSync(join(HERE, "..", "package.json"), "utf8"),
);

const server = new McpServer({ name: "mcp-objauthz-lab", version });
const store = createStore();
registerTools(server, store, modes);

const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
});
await server.connect(transport);

const readBody = (req) =>
  new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : undefined);
      } catch {
        resolve(undefined);
      }
    });
  });

const httpServer = createServer(async (req, res) => {
  const body = req.method === "POST" ? await readBody(req) : undefined;
  await transport.handleRequest(req, res, body);
});

const port = Number(process.env.PORT ?? 3010);
httpServer.listen(port, () => {
  console.error(
    `[mcp-objauthz-lab:http] up on :${port}  S10=${modes.s10}  S11=${modes.s11}  S12=${modes.s12}  S13=${modes.s13}  (S1..S9 default vuln unless LAB_S* set)`,
  );
});
