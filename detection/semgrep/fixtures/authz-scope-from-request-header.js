// Test fixture for rule: mcp-authz-scope-from-request-header
//
// S10 (forwarded-header-as-scope). Over the MCP streamable-HTTP transport a
// tool handler receives the request's headers in extra.requestInfo.headers.
// A server behind a gateway is tempted to trust a tenant/identity header
// (X-Org-Id, or X-Forwarded-For in the IP-scoping variant) as the
// authorization scope -- but that header is fully client-controlled.
// The rule REQUIRES the header value to reach an AUTHORIZATION DECISION
// (a store/list call that selects tenant scope, or an orgId binding in a query),
// not merely be read into a variable.
//
// TWO-WAY CANARY:
// - FIRE: header value feeds an authz decision (scope/org-id selection, listNotesByOrg(headerValue))
// - SILENT: header read ONLY for logging (no authz decision)

// FIRE: header value used to select org scope in a store call (authz decision)
async function noteGetScopedVuln({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-authz-scope-from-request-header
  const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
  const effectiveOrgId = headerOrg ? headerOrg : session.orgId;
  return store.listNotesByOrg(effectiveOrgId);
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
async function noteGetScopedByIpVuln({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-authz-scope-from-request-header
  const fwd = extra.requestInfo.headers["x-forwarded-for"];
  return store.listNotesForClientIp(fwd ?? session.clientIp);
}

// FIRE: header used directly as orgId in a query filter (authz decision)
async function noteGetByQueryVuln({ token, id }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-authz-scope-from-request-header
  const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
  return store.findNoteBy({ id, orgId: headerOrg ?? session.orgId });
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

// SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
// This is the two-way canary: reading XFF for logging must NOT fire.
async function logClientIp(_args, extra) {
  // ok: mcp-authz-scope-from-request-header
  const clientIp = extra?.requestInfo?.headers?.["x-forwarded-for"];
  logger.info({ clientIp, msg: "rate-limit check" });
}

// SILENT: scope-shaped header read into a variable but NEVER used for authz
async function readHeaderButDontUse({ token }, extra) {
  const session = resolveSession(store, token);
  // ok: mcp-authz-scope-from-request-header
  const _unused = extra?.requestInfo?.headers?.["x-org-id"];
  return store.listNotesByOrg(session.orgId);
}