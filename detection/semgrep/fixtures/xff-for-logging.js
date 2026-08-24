// Real-capture fixture for rule: mcp-authz-scope-from-request-header
//
// From audit: SurfSense and other real MCP servers read X-Forwarded-For for
// logging/analytics ONLY, not for authorization. The hardened rule must NOT
// fire on this pattern — it's the SILENT half of the two-way canary.
//
// SILENT: X-Forwarded-For read ONLY for logging, no authz decision.

async function logRequestForAnalytics(_args, extra) {
  // ok: mcp-authz-scope-from-request-header
  const clientIp = extra?.requestInfo?.headers?.["x-forwarded-for"];
  logger.info({ clientIp, event: "tool_call", timestamp: Date.now() });
}

async function logRequestWithXRealIp(_args, extra) {
  // ok: mcp-authz-scope-from-request-header
  const clientIp = extra?.requestInfo?.headers?.["x-real-ip"];
  logger.info({ clientIp, event: "tool_call" });
}

async function logRequestWithXClientIp(_args, extra) {
  // ok: mcp-authz-scope-from-request-header
  const clientIp = extra?.requestInfo?.headers?.["x-client-ip"];
  logger.info({ clientIp, event: "tool_call" });
}