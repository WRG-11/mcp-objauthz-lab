// Test fixture for rule: mcp-batch-resolve-missing-per-item-scope-filter

async function vulnBatchGet({ token, ids }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-batch-resolve-missing-per-item-scope-filter
  const resolved = ids.map((id) => store.getNote(id));
  return ok(resolved);
}

async function fixedBatchGet({ token, ids }) {
  const session = resolveSession(store, token);
  const resolved = ids.map((id) => store.getNote(id));
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  const scoped = resolved.filter((n) => n.orgId === session.orgId);
  return ok(scoped);
}
