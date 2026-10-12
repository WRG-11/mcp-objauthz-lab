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

// The per-USER spelling of the same bug. CVE-2026-9135 (IBM Langflow) is the
// shape below, verbatim: an MCP tool that accepts a caller-supplied user_id
// and uses it to select whose flow to modify. The rule did not cover this
// name until that CVE showed it was the one attackers actually reach for.
async function vulnUpdateFlowField({ token, flow_id, field, value, user_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-client-supplied-scope-overrides-session
  const effectiveUserId = user_id || session.userId;
  return ok(store.updateFlowField(effectiveUserId, flow_id, field, value));
}

async function fixedUpdateFlowField({ token, flow_id, field, value, user_id }) {
  const session = resolveSession(store, token);
  // ok: mcp-client-supplied-scope-overrides-session
  const effectiveUserId = session.userId;
  return ok(store.updateFlowField(effectiveUserId, flow_id, field, value));
}

// owner_id, and the ?? spelling of the fallback.
async function vulnGetDoc({ token, doc_id, owner_id }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-client-supplied-scope-overrides-session
  const effectiveOwner = owner_id ?? session.ownerId;
  return ok(store.getDoc(effectiveOwner, doc_id));
}

async function fixedGetDoc({ token, doc_id, owner_id }) {
  const session = resolveSession(store, token);
  // ok: mcp-client-supplied-scope-overrides-session
  return ok(store.getDoc(session.ownerId, doc_id));
}
