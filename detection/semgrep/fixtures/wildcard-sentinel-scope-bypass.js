// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass

async function vulnExport({ token, org_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-wildcard-sentinel-scope-bypass
  if (org_id === "*" || org_id === "all") {
    return ok(store.listAllNotes());
  }
  return ok(store.listNotesByOrg(session.orgId));
}

async function fixedExportGuarded({ token, org_id }) {
  const session = resolveSession(store, token);
  requireAdminRole(session);
  // ok: mcp-wildcard-sentinel-scope-bypass
  if (org_id === "*" || org_id === "all") {
    return ok(store.listAllNotes());
  }
  return ok(store.listNotesByOrg(session.orgId));
}
