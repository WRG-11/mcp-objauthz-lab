// Test fixture for rule: mcp-write-parent-from-client-argument
//
// The write side of object-level authz. Every other rule in this set guards a
// read; this one guards a create. The bug is that the DESTINATION of the write
// comes from the caller instead of the session, so a caller who cannot read
// another tenant's data can still plant data inside it.
//
// The `ok:` cases matter as much as the `ruleid:` ones here. A rule that fires
// on every create taking an org argument would flag legitimate cross-team
// tools, get switched off, and protect nothing.

// The plainest form: the argument is the write target.
async function createNoteVuln({ token, org_id, title }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-write-parent-from-client-argument
  return store.createNote({ orgId: org_id, ownerId: session.userId, title });
}

// Same bug wearing a local variable. This is the shape the lab itself has, and
// the one a reviewer skims past because the write line looks session-free.
async function createNoteVuluViaLocal({ token, org_id, title }) {
  const session = resolveSession(store, token);
  const targetOrgId = org_id;
  // ruleid: mcp-write-parent-from-client-argument
  return store.createNote({ orgId: targetOrgId, ownerId: session.userId, title });
}

// Straight off the args object, no destructuring to make it visible.
async function createRecordVuln(args) {
  const session = resolveSession(store, args.token);
  // ruleid: mcp-write-parent-from-client-argument
  return store.createRecord({ workspaceId: args.workspaceId, ownerId: session.userId });
}

// ORM spelling of the same omission.
async function saveDocVuln({ token, tenant_id, body }) {
  const session = resolveSession(store, token);
  // ruleid: mcp-write-parent-from-client-argument
  return repo.save({ tenantId: tenant_id, authorId: session.userId, body });
}

// Correct: the destination is the session's own scope and the argument, if
// any, is ignored.
async function createNoteSafe({ token, org_id, title }) {
  const session = resolveSession(store, token);
  // ok: mcp-write-parent-from-client-argument
  return store.createNote({ orgId: session.orgId, ownerId: session.userId, title });
}

// Correct: a cross-team tool that genuinely accepts a destination, and proves
// membership of it first. Flagging this one would be the false positive that
// gets the rule disabled.
async function createNoteSafeChecked({ token, org_id, title }) {
  const session = resolveSession(store, token);
  requireOrgAccess(session, org_id);
  // ok: mcp-write-parent-from-client-argument
  return store.createNote({ orgId: org_id, ownerId: session.userId, title });
}

// Correct: a write with no tenant-shaped key at all is not this rule's
// business, however many arguments it takes.
async function createCommentSafe({ token, note_id, body }) {
  const session = resolveSession(store, token);
  // ok: mcp-write-parent-from-client-argument
  return store.createComment({ noteId: note_id, authorId: session.userId, body });
}
