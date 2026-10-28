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

// VULN: the later filter only drops missing ids; it never compares the
// caller's scope, so it is not the per-item check.
async function batchResolveDropMissing({ ids }) {
  // ruleid: mcp-batch-resolve-missing-per-item-scope-filter
  const notes = ids.map(id => store.getNote(id));
  return notes.filter(n => n !== undefined);
}

// OK: the scope filter is chained onto the batch read.
async function batchResolveChained({ ids, session }) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  return ids.map(id => store.getNote(id)).filter(n => n.orgId == session.orgId);
}

// OK: the scope filter runs later on a plain batch read.
async function batchResolveThenScope({ ids, session }) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  const notes = ids.map(id => store.getNote(id));
  return notes.filter(n => n.tenantId === session.tenantId);
}

// OK: the chained scope filter with `===`.
async function batchResolveChainedStrict({ ids, session }) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  return ids.map(id => store.getNote(id)).filter(n => n.orgId === session.orgId);
}

// OK: the later scope filter with `==`.
async function batchResolveThenScopeLoose({ ids, session }) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  const notes = ids.map(id => store.getNote(id));
  return notes.filter(n => n.orgId == session.orgId);
}

// VULN: the filter compares the item's org with the caller's user id, two
// different keys, so it never limits the batch to the caller's org.
async function batchResolveWrongKey({ ids, session }) {
  // ruleid: mcp-batch-resolve-missing-per-item-scope-filter
  const notes = ids.map(id => store.getNote(id));
  return notes.filter(n => n.orgId === session.userId);
}
