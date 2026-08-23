// Test fixture for rule: mcp-missing-object-authz-check

async function vulnDelete({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  // ruleid: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

async function fixedDelete({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  requireOrgAccess(session, note);
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

// The pure-read spelling of the same defect. For most of this rule's life the
// `return ok($OBJ)` branch existed but had never fired (see the rule comment):
// a cross-tenant READ went unseen while the mutation was caught. These two
// cases pin both halves now that the branch is live.
async function vulnRead({ token, id }) {
  const session = resolveSession(store, token);
  const doc = store.getDoc(id);
  // ruleid: mcp-missing-object-authz-check
  return ok(doc);
}

async function fixedRead({ token, id }) {
  const session = resolveSession(store, token);
  const doc = store.getDoc(id);
  requireOwnership(session, doc);
  // ok: mcp-missing-object-authz-check
  return ok(doc);
}
