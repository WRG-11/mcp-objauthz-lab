// Test fixture for rule: mcp-authz-scope-from-request-header
//
// S10 (forwarded-header-as-scope). Over the MCP streamable-HTTP transport a
// tool handler receives the request's headers in extra.requestInfo.headers.
// A server behind a gateway is tempted to trust a tenant/identity header
// (X-Org-Id, or X-Forwarded-For in the IP-scoping variant) as the
// authorization scope — but that header is fully client-controlled. The
// legitimate-neighbor case reads a NON-scope header (X-Request-Id) for
// logging, which must stay silent: the rule keys on the header NAME, not on
// the mere act of reading a header.

// VULN: a scope-shaped header selects whose notes are returned.
async function noteGetScopedVuln({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-authz-scope-from-request-header
  const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
  const effectiveOrgId = headerOrg ? headerOrg : session.orgId;
  return store.listNotesByOrg(effectiveOrgId);
}

// VULN (IP-scoping variant): X-Forwarded-For trusted for the same purpose.
async function noteGetScopedByIpVuln({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-authz-scope-from-request-header
  const fwd = extra.requestInfo.headers["x-forwarded-for"];
  return store.listNotesForClientIp(fwd ?? session.clientIp);
}

// OK: scope comes from the session; no header is consulted at all.
async function noteGetScopedFixed({ token }, extra) {
  const session = resolveSession(store, token);
  // ok: mcp-authz-scope-from-request-header
  return store.listNotesByOrg(session.orgId);
}

// OK (legitimate neighbor): a non-scope header read for logging only. The
// scope-header name regex must not match "x-request-id".
async function logRequest(_args, extra) {
  // ok: mcp-authz-scope-from-request-header
  const reqId = extra?.requestInfo?.headers?.["x-request-id"];
  logger.info({ reqId, msg: "tool invoked" });
}
