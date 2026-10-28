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

// The check written inline instead of as a guard call: the object's scope key
// compared with the session's, before the object is used. This is the lab's
// own note_get, and the rule reported it until the inline form was exempted.
async function fixedReadInline({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (!note || note.orgId !== session.orgId) unavailable();
  // ok: mcp-missing-object-authz-check
  return ok(note);
}

async function fixedReadInlineLoose({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (!note || note.orgId != session.orgId) unavailable();
  // ok: mcp-missing-object-authz-check
  return ok(note);
}

async function fixedDeleteInlineReversed({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (session.orgId !== note.orgId) throw new Error("not found");
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

async function fixedDeleteInlineReversedLoose({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (session.orgId != note.orgId) throw new Error("not found");
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

async function fixedDeleteInlineStrict({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (note.orgId !== session.orgId) throw new Error("not found");
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

async function fixedReadInlineReversedStrict({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (!note || session.orgId !== note.orgId) unavailable();
  // ok: mcp-missing-object-authz-check
  return ok(note);
}

async function fixedDeleteInlineLoose({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (note.orgId != session.orgId) throw new Error("not found");
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

async function fixedReadInlineReversedLoose({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (!note || session.orgId != note.orgId) unavailable();
  // ok: mcp-missing-object-authz-check
  return ok(note);
}

// VULN: the comparison uses two different keys (the note's org against the
// caller's user id), so it does not limit the read to the caller's org.
async function vulnReadWrongKey({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (!note || note.orgId !== session.userId) unavailable();
  // ruleid: mcp-missing-object-authz-check
  return ok(note);
}
