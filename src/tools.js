// MCP tool definitions.
//
// Six note tools (list / get / create / update / delete / search) plus a small
// `whoami` helper. Five of the six object tools are correctly authorized:
// every tool that resolves an object by its client-supplied id calls
// requireOrgAccess() before returning or mutating it.
//
// EXACTLY ONE is not:  note_delete  (when LAB_MODE=vuln).
// That single missing check is the whole lab. Read note_get and note_update
// first, then note_delete — the only difference is the absent org-scope line.

import { z } from "zod";
import {
  resolveSession,
  requireOrgAccess,
  AuthnError,
  AuthzError,
  NotFoundError,
} from "./auth.js";

// ── result helpers (MCP tool result shape) ─────────────────────────────────
const ok = (obj) => ({
  content: [{ type: "text", text: JSON.stringify(obj, null, 2) }],
});
const fail = (message) => ({
  content: [{ type: "text", text: JSON.stringify({ error: message }) }],
  isError: true,
});

// Turn our typed errors into clean MCP error results instead of crashes.
const guard = (handler) => async (args) => {
  try {
    return await handler(args);
  } catch (err) {
    if (
      err instanceof AuthnError ||
      err instanceof AuthzError ||
      err instanceof NotFoundError
    ) {
      return fail(`${err.constructor.name}: ${err.message}`);
    }
    throw err;
  }
};

const notFound = (id) => {
  throw new NotFoundError(`no such note: ${id}`);
};

/**
 * Register every tool on the server.
 * @param {import("@modelcontextprotocol/sdk/server/mcp.js").McpServer} server
 * @param {ReturnType<import("./store.js").createStore>} store
 * @param {"vuln"|"fixed"} mode
 */
export function registerTools(server, store, mode) {
  // whoami — echoes the server-trusted session (handy to see token -> org).
  server.registerTool(
    "whoami",
    {
      description: "Return the session (user + org) your token authenticates as.",
      inputSchema: { token: z.string() },
    },
    guard(async ({ token }) => ok(resolveSession(store, token))),
  );

  // note_list — inherently org-scoped: only ever lists the caller's org.
  server.registerTool(
    "note_list",
    {
      description: "List the notes in your organization.",
      inputSchema: { token: z.string() },
    },
    guard(async ({ token }) => {
      const session = resolveSession(store, token);
      return ok(store.listNotesByOrg(session.orgId));
    }),
  );

  // note_get — resolves an object by client-supplied id. CORRECTLY authorized.
  server.registerTool(
    "note_get",
    {
      description: "Get one note by id.",
      inputSchema: { token: z.string(), id: z.string() },
    },
    guard(async ({ token, id }) => {
      const session = resolveSession(store, token);
      const note = store.getNote(id);
      if (!note) notFound(id);
      requireOrgAccess(session, note); // org-scope check (present)
      return ok(note);
    }),
  );

  // note_create — creates inside the caller's org; no foreign id involved.
  server.registerTool(
    "note_create",
    {
      description: "Create a note in your organization.",
      inputSchema: {
        token: z.string(),
        title: z.string(),
        body: z.string().optional(),
      },
    },
    guard(async ({ token, title, body }) => {
      const session = resolveSession(store, token);
      const note = store.createNote({
        orgId: session.orgId,
        ownerId: session.userId,
        title,
        body,
      });
      return ok(note);
    }),
  );

  // note_update — resolves an object by client-supplied id. CORRECTLY authorized.
  server.registerTool(
    "note_update",
    {
      description: "Update a note's body by id.",
      inputSchema: { token: z.string(), id: z.string(), body: z.string() },
    },
    guard(async ({ token, id, body }) => {
      const session = resolveSession(store, token);
      const note = store.getNote(id);
      if (!note) notFound(id);
      requireOrgAccess(session, note); // org-scope check (present)
      return ok(store.updateNote(id, { body }));
    }),
  );

  // ── note_delete ───────────────────────────────────────────────────────────
  // THE PLANTED BUG — object-level / cross-tenant BOLA (CWE-639 / CWE-862).
  //
  // Compare with note_get and note_update directly above: all three resolve a
  // note from a client-supplied `id`. Those two then call requireOrgAccess()
  // to confirm the note belongs to the caller's org. note_delete does not — in
  // LAB_MODE=vuln the org-scope line is missing, so ANY caller can delete ANY
  // org's note simply by knowing (or guessing) its id.
  //
  // The fix is the single line marked `// <-- THE FIX`: the very same check its
  // sibling tools already perform. It is applied only in LAB_MODE=fixed so the
  // PoC can demonstrate both states (vuln = exploit, fixed = blocked).
  server.registerTool(
    "note_delete",
    {
      description: "Delete a note by id.",
      inputSchema: { token: z.string(), id: z.string() },
    },
    guard(async ({ token, id }) => {
      const session = resolveSession(store, token);
      const note = store.getNote(id);
      if (!note) notFound(id);
      if (mode === "fixed") requireOrgAccess(session, note); // <-- THE FIX (absent in vuln mode)
      store.deleteNote(note.id);
      return ok({ deleted: note.id, title: note.title });
    }),
  );

  // note_search — cross-cutting query, scoped to the caller's org.
  server.registerTool(
    "note_search",
    {
      description: "Search your organization's notes by substring.",
      inputSchema: { token: z.string(), q: z.string() },
    },
    guard(async ({ token, q }) => {
      const session = resolveSession(store, token);
      return ok(store.searchNotesByOrg(session.orgId, q));
    }),
  );
}
