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
