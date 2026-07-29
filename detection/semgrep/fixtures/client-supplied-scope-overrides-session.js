// Test fixture for rule: mcp-client-supplied-scope-overrides-session

async function vulnSearch({ token, q, org_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-client-supplied-scope-overrides-session
  const effectiveOrgId = org_id || session.orgId;
  return ok(store.searchNotesByOrg(effectiveOrgId, q));
}

async function fixedSearch({ token, q, org_id }) {
  const session = resolveSession(store, token);
  // ok: mcp-client-supplied-scope-overrides-session
  const effectiveOrgId = session.orgId;
  return ok(store.searchNotesByOrg(effectiveOrgId, q));
}
