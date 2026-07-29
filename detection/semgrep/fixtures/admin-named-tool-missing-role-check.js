// Test fixture for rule: mcp-admin-named-tool-missing-role-check

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

server.registerTool(
  // ok: mcp-admin-named-tool-missing-role-check
  "note_admin_get",
  { inputSchema: { token: z.string(), id: z.string() } },
  guard(async ({ token, id }) => {
    const session = resolveSession(store, token);
    requireAdminRole(session);
    const note = store.getNote(id);
    return ok(note);
  }),
);
