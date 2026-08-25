// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass
//
// S4 (wildcard/sentinel bypass). A magic "all" or "*" sentinel on a scope
// parameter is honored in an AUTHORIZATION CONTEXT (it controls whether to
// widen scope and return all tenants' data) without a role check.
// A textual "*" or "all" comparison in markup rendering, UI filters, or
// logging is NOT an authz decision and must stay silent.
//
// TWO-WAY CANARY:
// - FIRE: wildcard in authz bypass context (gates scope widening, returns all orgs' data)
// - SILENT: wildcard in non-authz context (markup, UI filter, logging)

// FIRE: wildcard comparison gates returning all orgs' data (authz bypass)
async function vulnExport({ token, org_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-wildcard-sentinel-scope-bypass
  if (org_id === "*" || org_id === "all") {
    return ok(store.listAllNotes());
  }
  return ok(store.listNotesByOrg(session.orgId));
}

// FIRE: ternary with wildcard selecting all-orgs vs scoped data (authz bypass)
async function vulnExportTernary({ token, org_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-wildcard-sentinel-scope-bypass
  return ok(org_id === "*" ? store.listAllNotes() : store.listNotesByOrg(session.orgId));
}

// FIRE: wildcard check skips normal org scoping (authz bypass)
async function vulnExportSkipScope({ token, org_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-wildcard-sentinel-scope-bypass
  if (org_id === "*") {
    return ok(store.listAllNotes());
  }
  // no org scoping in this branch -- wildcard bypassed it
  return ok(store.listAllNotes());
}

// OK: wildcard guarded by admin role check
async function fixedExportGuarded({ token, org_id }) {
  const session = resolveSession(store, token);
  requireAdminRole(session);
  // ok: mcp-wildcard-sentinel-scope-bypass
  if (org_id === "*" || org_id === "all") {
    return ok(store.listAllNotes());
  }
  return ok(store.listNotesByOrg(session.orgId));
}

// SILENT: wildcard in markup rendering (textual, not authz)
// The parameter name matches scope regex but context is markup, not authz
function renderMarkdown(text) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  return text.replace(/\*(.+?)\*/g, "<b>$1</b>");
}

// SILENT: wildcard in UI search filter (textual comparison, not authz)
// The variable name matches scope regex but it's a UI filter value, not scope
function filterNotesByScope(notes, scope) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  if (scope === "all") {
    return notes; // UI "show all" filter, not authz bypass
  }
  return notes.filter((n) => n.scope === scope);
}

// SILENT: wildcard in logging (textual, not authz)
function logScopeValue(scope) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  if (scope === "*") {
    logger.info("wildcard scope requested");
  }
}