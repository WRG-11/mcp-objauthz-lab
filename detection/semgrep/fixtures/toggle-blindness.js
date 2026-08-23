// Test fixture: toggle blindness (S1 + S5) — the separating fixture.
//
// Background, measured 2026-08-23. Scanning this lab's own src/tools.js used
// to be cited as "the rules catch 5 of 7 scenarios", implying S1/S5 rules miss
// real-world bugs. That reading was wrong in BOTH directions:
//
//   - On production-shaped files (no runtime toggle, guard simply not written)
//     both rules DO fire — see missing-object-authz-check.js and
//     admin-named-tool-missing-role-check.js for those pairs.
//   - The lab's own source silences them only because its fix is a guard
//     written BEHIND a runtime toggle (`if (modes.s1 === "fixed") ...`), and
//     these rules work by checking that an authorization call textually
//     appears between resolve and sink.
//
// Decision (deliberate, measured): the rules do NOT see through toggles.
// Treating a conditionally-present guard as absent would mean flagging
// `if (config.strictAuthz) requireAccess(...)` — a legitimate production
// pattern, textually indistinguishable from the lab's toggle at this rule's
// matching depth. A gate that wide produces the false positives that get a
// rule switched off, and narrowing it to the lab's literal `"fixed"` spelling
// would tune the detector to its own lab. So the toggle-guarded middle case
// below is annotated ok ON PURPOSE: it pins the documented blindness so a
// future edit cannot widen or narrow it silently.


// ── S1: mcp-missing-object-authz-check ─────────────────────────────────────

// Production shape, toggle-free, guard never written: FIRES (same pair lives
// in missing-object-authz-check.js; repeated here so this file tells the
// whole story standalone).
async function deleteNoteNoToggleNoGuard({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  // ruleid: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

// The lab's own spelling: guard present but behind a runtime toggle. Stays
// silent by decision — see the header comment.
async function deleteNoteGuardBehindToggle({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  if (modes.s1 === "fixed") requireOrgAccess(session, note);
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}

// Unconditional check: silent, as everywhere.
async function deleteNoteUnconditionalGuard({ token, id }) {
  const session = resolveSession(store, token);
  const note = store.getNote(id);
  requireOrgAccess(session, note);
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
  return ok({ deleted: note.id });
}


// ── S5: mcp-admin-named-tool-missing-role-check ────────────────────────────

// Production shape, toggle-free, no role check: FIRES (same pair lives in
// admin-named-tool-missing-role-check.js; repeated for a standalone story).
server.registerTool(
  // ruleid: mcp-admin-named-tool-missing-role-check
  "note_admin_get",
  { inputSchema: { token: z.string(), id: z.string() } },
  guard(async ({ token, id }) => {
    const session = resolveSession(store, token);
    const note = store.getNote(id);
    return ok(note);
  }),
);

// The lab's own spelling: role check behind the runtime toggle. Silent by
// decision — see the header comment.
server.registerTool(
  "note_admin_get",
  { inputSchema: { token: z.string(), id: z.string() } },
  guard(async ({ token, id }) => {
    const session = resolveSession(store, token);
    if (modes.s5 === "fixed") requireAdminRole(session);
    // ok: mcp-admin-named-tool-missing-role-check
    const note = store.getNote(id);
    return ok(note);
  }),
);

server.registerTool(
  "note_admin_get",
  { inputSchema: { token: z.string(), id: z.string() } },
  guard(async ({ token, id }) => {
    const session = resolveSession(store, token);
    requireAdminRole(session);
    // ok: mcp-admin-named-tool-missing-role-check
    const note = store.getNote(id);
    return ok(note);
  }),
);
