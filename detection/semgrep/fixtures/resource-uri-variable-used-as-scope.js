// Test fixture: mcp-resource-uri-variable-used-as-scope (S8).

// Vulnerable: the URI template variable `orgId` is used directly as the
// scope in the store lookup. Whoever writes the URI chooses the tenant.
server.registerResource(
  "note",
  new ResourceTemplate("note://{token}/{orgId}/{noteId}", { list: undefined }),
  { title: "Note", description: "Read a single note as an MCP resource." },
  async (uri, { token, orgId, noteId }) => {
    const session = resolveSession(store, token);
    // ruleid: mcp-resource-uri-variable-used-as-scope
    return wrap(uri, store.findNoteBy({ id: noteId, orgId }));
  },
);

// Fixed: the URI still carries the orgId variable (removing it would be a
// breaking template change), but the scope comes from the session instead.
server.registerResource(
  "note",
  new ResourceTemplate("note://{token}/{orgId}/{noteId}", { list: undefined }),
  { title: "Note", description: "Read a single note as an MCP resource." },
  async (uri, { token, orgId, noteId }) => {
    const session = resolveSession(store, token);
    // ok: mcp-resource-uri-variable-used-as-scope
    return wrap(uri, store.findNoteBy({ id: noteId, orgId: session.orgId }));
  },
);

// Legitimate sibling: the URI template carries no tenant segment at all —
// only an identity token and the object id. There is no caller-writable
// scope value to trust in the first place.
server.registerResource(
  "note",
  new ResourceTemplate("note://{token}/{noteId}", { list: undefined }),
  { title: "Note", description: "Read a single note as an MCP resource." },
  async (uri, { token, noteId }) => {
    const session = resolveSession(store, token);
    // ok: mcp-resource-uri-variable-used-as-scope
    return wrap(uri, store.findNoteBy({ id: noteId, orgId: session.orgId }));
  },
);
