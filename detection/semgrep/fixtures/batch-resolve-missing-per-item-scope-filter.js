// Test fixture for rule: mcp-batch-resolve-missing-per-item-scope-filter
//
// S12 (batch/bulk endpoint BOLA). A batch endpoint resolves multiple ids
// but skips the per-item org check. The sibling list() tool is correctly scoped
// while the batch-get sibling skips the per-object check — the "list->get
// asymmetry" pattern at batch scale.
//
// Two-way canary axis: is there a per-item filter back to the caller's scope?
// (present ⇒ SILENT)

async function batchResolveVuln({ ids }) {
  // ruleid: mcp-batch-resolve-missing-per-item-scope-filter
  return ids.map(id => store.getNote(id)).filter(Boolean);
}

async function batchResolveSafe({ ids, session }) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  const resolved = ids.map(id => store.getNote(id)).filter(Boolean);
  return resolved.filter(n => n.orgId === session.orgId);
}

async function batchResolveWithFilter({ ids, session }) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  const resolved = ids.map(id => store.getNote(id)).filter(Boolean);
  return resolved.filter(n => n.orgId === session.orgId);
}