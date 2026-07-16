// MCP tool definitions — 4 independent BOLA scenarios.
//
// Tool inventory:
//
//   whoami          — echo session (user + org); no authz involved
//   note_list       — inherently org-scoped; no BOLA
//   note_get        — correctly authorized (compare: note_delete in S1 vuln)
//   note_create     — creates inside caller's org; no foreign id
//   note_update     — correctly authorized
//   note_delete  ← S1 planted bug: missing requireOrgAccess() in vuln mode
//   note_search  ← S2 planted bug: trusts caller-supplied org_id (scope-as-param)
//   note_batch_get  ← S3 planted bug: resolves ids without per-object org check (list→get asymmetry)
//   note_export  ← S4 planted bug: wildcard sentinel "* / all" bypasses org scope
//   note_admin_get      ← S5 planted bug: admin-named tool has no role check (role/token-type bypass)
//   note_create_in_org  ← S6 planted bug: trusts caller-supplied org_id as write target (foreign-parent injection)
//
// Each scenario is gated by its own mode flag (modes.s1..s6 = "vuln" | "fixed").
// Scenarios are independent: you can set any combination to "fixed" to isolate one.

import { z } from "zod";
import {
  resolveSession,
  requireOrgAccess,
  requireAdminRole,
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
 * @param {{ s1: "vuln"|"fixed", s2: "vuln"|"fixed", s3: "vuln"|"fixed", s4: "vuln"|"fixed", s5: "vuln"|"fixed", s6: "vuln"|"fixed" }} modes
 */
export function registerTools(server, store, modes) {
  // whoami — echoes the server-trusted session (handy to verify token → org mapping).
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
      requireOrgAccess(session, note); // org-scope check (present — compare note_delete in S1 vuln)
      return ok(note);
    }),
  );

  // note_create — creates inside the caller's org; no foreign object id involved.
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

  // ── S1: note_delete ───────────────────────────────────────────────────────
  // THE ORIGINAL PLANTED BUG — object-level / cross-tenant BOLA (CWE-639 / CWE-862).
  //
  // Compare with note_get and note_update above: all three resolve a note from a
  // client-supplied `id`. Those two then call requireOrgAccess(). note_delete
  // does not in vuln mode — ANY caller can delete ANY org's note by knowing its id.
  //
  // The fix is the single line marked `// <-- THE FIX`.
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
      if (modes.s1 === "fixed") requireOrgAccess(session, note); // <-- THE FIX (absent in vuln mode)
      store.deleteNote(note.id);
      return ok({ deleted: note.id, title: note.title });
    }),
  );

  // ── S2: note_search ───────────────────────────────────────────────────────
  // SCOPE-AS-PARAM BOLA (CWE-639).
  //
  // The tool accepts an optional `org_id` parameter that is documented as "admin use."
  // In vuln mode the server trusts it unconditionally — any caller can set it to any
  // other org's id and receive that org's notes.
  //
  //   Exploit: Alice (org_acme) calls note_search with org_id="org_globex" → Globex notes.
  //
  // In fixed mode the parameter is accepted in the schema (removing it would be a
  // breaking API change) but silently ignored; session.orgId is always used.
  server.registerTool(
    "note_search",
    {
      description:
        "Search notes by substring. The optional org_id parameter restricts the scope (admin use).",
      inputSchema: {
        token: z.string(),
        q: z.string(),
        org_id: z.string().optional(),
      },
    },
    guard(async ({ token, q, org_id }) => {
      const session = resolveSession(store, token);
      // S2 vuln: trust caller-supplied org_id if present.
      // S2 fixed: always use session.orgId (org_id ignored).
      const effectiveOrgId =
        modes.s2 === "vuln" && org_id ? org_id : session.orgId;
      return ok(store.searchNotesByOrg(effectiveOrgId, q));
    }),
  );

  // ── S3: note_batch_get ────────────────────────────────────────────────────
  // LIST→GET ASYMMETRY BOLA (CWE-862).
  //
  // A common pattern: `note_list` is safely org-scoped, but `note_batch_get`
  // accepts a list of explicit ids and resolves each one directly from storage
  // without re-applying the org scope check. An attacker who knows (or guesses)
  // note ids from another org can mix them into the batch and receive them.
  //
  //   Exploit: Alice knows n_acme_1 (her note). She also passes n_globex_1.
  //            In vuln mode both are returned; she reads Globex's note.
  //
  // In fixed mode resolved notes are filtered to session.orgId before returning.
  server.registerTool(
    "note_batch_get",
    {
      description: "Fetch multiple notes by id in a single call (up to 20 ids).",
      inputSchema: {
        token: z.string(),
        ids: z.array(z.string()).min(1).max(20),
      },
    },
    guard(async ({ token, ids }) => {
      const session = resolveSession(store, token);
      const resolved = ids.map((id) => store.getNote(id)).filter(Boolean);
      // S3 vuln: return all resolved notes with no org check.
      // S3 fixed: filter to caller's org before returning.
      const result =
        modes.s3 === "vuln"
          ? resolved
          : resolved.filter((n) => n.orgId === session.orgId);
      return ok(result);
    }),
  );

  // ── S4: note_export ───────────────────────────────────────────────────────
  // WILDCARD / SENTINEL BYPASS BOLA (CWE-639).
  //
  // The tool exports all notes for a given org. A magic sentinel value ("*" or
  // "all") is supposed to be admin-only, but in vuln mode the server honors it
  // from any caller — letting them dump every note from every tenant.
  //
  //   Exploit: Alice passes org_id="*" → receives notes from Acme, Globex, AND Initech.
  //
  // In fixed mode the org_id parameter is fully ignored and only the caller's org
  // is exported, regardless of what value is supplied.
  server.registerTool(
    "note_export",
    {
      description:
        "Export all notes for an organization. Pass org_id='*' for a global export (admin only).",
      inputSchema: {
        token: z.string(),
        org_id: z.string().optional(),
      },
    },
    guard(async ({ token, org_id }) => {
      const session = resolveSession(store, token);
      // S4 vuln: honor sentinel values from any caller.
      // S4 fixed: ignore org_id entirely; always export caller's own org.
      if (modes.s4 === "vuln" && (org_id === "*" || org_id === "all")) {
        return ok(store.listAllNotes());
      }
      return ok(store.listNotesByOrg(session.orgId));
    }),
  );

  // ── S5: note_admin_get ───────────────────────────────────────────────────
  // ROLE / TOKEN-TYPE BYPASS BOLA (CWE-863).
  //
  // Support/ops tooling often needs a cross-tenant "view any note" escape
  // hatch for legitimate admins. The tool is named and documented as
  // admin-only, but in vuln mode nothing actually VERIFIES the caller holds
  // the admin role — any valid token reaches the cross-org lookup. Naming a
  // tool "admin_*" is documentation, not enforcement.
  //
  //   Exploit: Bob (ordinary user, org Globex) calls note_admin_get with
  //            Acme's note id → in vuln mode the object is returned; the
  //            tool never checked whether Bob is an admin at all.
  //
  // In fixed mode requireAdminRole(session) runs first — ordinary users are
  // denied, and Dana (the one real admin token) still succeeds, proving the
  // fix does not over-block legitimate admin use.
  server.registerTool(
    "note_admin_get",
    {
      description:
        "Get any note by id, across organizations. Admin/support use only.",
      inputSchema: { token: z.string(), id: z.string() },
    },
    guard(async ({ token, id }) => {
      const session = resolveSession(store, token);
      if (modes.s5 === "fixed") requireAdminRole(session); // <-- THE FIX (absent in vuln mode)
      const note = store.getNote(id);
      if (!note) notFound(id);
      return ok(note);
    }),
  );

  // ── S6: note_create_in_org ───────────────────────────────────────────────
  // FOREIGN-PARENT INJECTION BOLA (CWE-639).
  //
  // A cross-team collaboration tool lets a caller create a note "in" a
  // specified org. In vuln mode the server trusts the caller-supplied
  // org_id with no membership check — any caller can inject a note into an
  // org they do not belong to. Unlike S1-S4 (all reads or a delete), this is
  // a WRITE-side BOLA: it poisons another tenant's data instead of leaking it.
  //
  //   Exploit: Alice (org Acme) calls note_create_in_org with
  //            org_id="org_globex" → in vuln mode the note is created with
  //            orgId "org_globex" and shows up in Globex's note_list /
  //            note_search, despite Alice never being a Globex member.
  //
  // In fixed mode org_id is accepted in the schema (avoids a breaking API
  // change, same convention as S2/S4) but ignored; the note is always
  // created inside session.orgId.
  server.registerTool(
    "note_create_in_org",
    {
      description:
        "Create a note inside a specific organization (cross-team collaboration). The org_id parameter targets the destination org.",
      inputSchema: {
        token: z.string(),
        org_id: z.string().optional(),
        title: z.string(),
        body: z.string().optional(),
      },
    },
    guard(async ({ token, org_id, title, body }) => {
      const session = resolveSession(store, token);
      // S6 vuln: trust caller-supplied org_id as the creation target.
      // S6 fixed: always create inside session.orgId (org_id ignored).
      const targetOrgId =
        modes.s6 === "vuln" && org_id ? org_id : session.orgId;
      const note = store.createNote({
        orgId: targetOrgId,
        ownerId: session.userId,
        title,
        body,
      });
      return ok(note);
    }),
  );
}
