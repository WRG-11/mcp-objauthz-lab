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
//
// The rule is a taint rule, so a finding sits on the SINK: the call argument
// that selects the scope. `ruleid:` markers are therefore above the scoping
// call, not above the header read.

// FIRE: header value used to select org scope in a store call (authz decision)
async function noteGetScopedVuln({ token }, extra) {
  const session = resolveSession(store, token);
  const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
  const effectiveOrgId = headerOrg ? headerOrg : session.orgId;
  // ruleid: mcp-authz-scope-from-request-header
  return store.listNotesByOrg(effectiveOrgId);
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
async function noteGetScopedByIpVuln({ token }, extra) {
  const session = resolveSession(store, token);
  const fwd = extra.requestInfo.headers["x-forwarded-for"];
  // ruleid: mcp-authz-scope-from-request-header
  return store.listNotesForClientIp(fwd ?? session.clientIp);
}

// FIRE: header used directly as orgId in a query filter (authz decision)
async function noteGetByQueryVuln({ token, id }, extra) {
  const session = resolveSession(store, token);
  const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
  // ruleid: mcp-authz-scope-from-request-header
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

// FIRE: Fetch-style Headers object (.get) feeding a scoping call.
async function projectListVuln(_args, extra) {
  const tenant = extra.requestInfo.headers.get("x-tenant-id");
  // ruleid: mcp-authz-scope-from-request-header
  return store.findProjects(tenant);
}

// FIRE: optional-chained .get, the header picks the workspace.
async function workspaceSearchVuln({ query }, req) {
  const ws = req?.headers?.get("x-workspace-id");
  // ruleid: mcp-authz-scope-from-request-header
  return store.searchDocuments(query, ws);
}

// OK (legitimate neighbor): a correlation header passed to a list call is not
// a scope. Pins the header-name regex.
async function listByRequestId(_args, extra) {
  const reqId = extra?.requestInfo?.headers?.["x-request-id"];
  // ok: mcp-authz-scope-from-request-header
  return store.listAuditEvents(reqId);
}

// OK: the client IP is recorded, not used to choose whose data is returned.
// Pins the scoping-method regex.
async function recordClientIp({ token }, extra) {
  const session = resolveSession(store, token);
  const clientIp = extra?.requestInfo?.headers?.["x-forwarded-for"];
  // ok: mcp-authz-scope-from-request-header
  store.recordAccess(clientIp, session.userId);
  return store.listNotesByOrg(session.orgId);
}

// OK: the header lands in a non-scope field of a query object; the scope key
// comes from the session. Pins the object-argument exclusion and the
// scope-key regex.
async function listEventsFromIp({ token }, extra) {
  const session = resolveSession(store, token);
  const clientIp = extra?.requestInfo?.headers?.["x-forwarded-for"];
  // ok: mcp-authz-scope-from-request-header
  return store.listEvents({ orgId: session.orgId, sourceIp: clientIp });
}

// OK: a quota lookup keyed on a forwarded header is S11. It belongs to
// mcp-ratelimit-scope-from-forwarded-header, not to this rule.
async function quotaByForwardedIp({ token }, extra) {
  const session = resolveSession(store, token);
  const fwd = extra?.requestInfo?.headers?.["x-forwarded-for"];
  // ok: mcp-authz-scope-from-request-header
  if (store.getQuotaCount(fwd) >= 10) throw new Error("Quota exceeded");
  return store.listNotesByOrg(session.orgId);
}

// OK: the header org reaches three calls, and none of them chooses whose data
// is returned: an audit write, a quota lookup, and a non-scope field of an
// object passed next to the session scope.
async function auditAndQuotaByHeaderOrg({ token }, extra) {
  const session = resolveSession(store, token);
  const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
  // ok: mcp-authz-scope-from-request-header
  store.recordAccess({ orgId: headerOrg, userId: session.userId });
  // ok: mcp-authz-scope-from-request-header
  if (store.getQuotaCount({ orgId: headerOrg }) >= 10) throw new Error("Quota exceeded");
  // ok: mcp-authz-scope-from-request-header
  return store.listNotes(session.orgId, { traceOrg: headerOrg });
}
