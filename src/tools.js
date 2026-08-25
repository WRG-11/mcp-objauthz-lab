// MCP tool definitions — 8 independent BOLA scenarios across 14 tools, plus
// S8 on the resources/read surface.
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
//   note_get_by_query   — S7 planted bug: tenant key omitted from the query filter (unscoped query)
//   note_share_prepare  — correctly authorized: mints an opaque grant for the caller's own note
//   note_share_redeem  ← S9 planted bug: serves whatever noteId is inside the decoded grant,
//     with no re-check against the redeeming session (authz-from-client-round-tripped-value)
//
// Resource inventory:
//
//   note://{token}/{orgId}/{noteId}  ← S8 planted bug: scope read from the URI
//     the caller wrote, instead of the session (resources/read surface)
//
// Each scenario is gated by its own mode flag (modes.s1..s9 = "vuln" | "fixed").
// Scenarios are independent: you can set any combination to "fixed" to isolate one.

import { z } from "zod";
import { ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
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
// `extra` (the SDK's RequestHandlerExtra) is forwarded so a handler that needs
// the transport-level request context — e.g. HTTP headers via
// extra.requestInfo — can reach it. Handlers that ignore it are unaffected.
const guard = (handler) => async (args, extra) => {
  try {
    return await handler(args, extra);
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
 * @param {{ s1: "vuln"|"fixed", s2: "vuln"|"fixed", s3: "vuln"|"fixed", s4: "vuln"|"fixed", s5: "vuln"|"fixed", s6: "vuln"|"fixed", s7: "vuln"|"fixed", s8: "vuln"|"fixed", s9: "vuln"|"fixed", s10: "vuln"|"fixed", s11: "vuln"|"fixed", s12: "vuln"|"fixed", s13: "vuln"|"fixed" }} modes
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
  // ── S7: note_get_by_query ─────────────────────────────────────────────────
  // UNSCOPED-QUERY BOLA (CWE-639) — the query-scoped shape.
  //
  // S1's outlier hides a MISSING guard *call* (resolve-by-id, then forget
  // requireOrgAccess). Real MCP servers rarely look like that. They bind the
  // tenant INTO the query: `repo.findOneBy({ id, workspaceId })`. The bug in
  // that world is quieter — the tenant key is simply left out of the filter,
  // so the WHERE matches on id alone and any caller's id resolves regardless
  // of org. There is no missing guard line to spot; the omission is one key
  // inside an object.
  //
  // This is the shape CVE-2026-54052 (n8n, CVSS 9.6) took: a table fetched by
  // a sequential id with the tenant column left out of the query, letting any
  // caller read another tenant's stored secrets. A guard-call detector (S1)
  // never sees it, because there is no guard call to be missing.
  //
  // S7 vuln:  store.findNoteBy({ id })                        — tenant key omitted
  // S7 fixed: store.findNoteBy({ id, orgId: session.orgId })  — tenant key bound
  server.registerTool(
    "note_get_by_query",
    {
      description:
        "Fetch a single note by id, resolved through a filtered store query.",
      inputSchema: {
        token: z.string(),
        id: z.string(),
      },
    },
    guard(async ({ token, id }) => {
      const session = resolveSession(store, token);
      const note =
        modes.s7 === "vuln"
          ? store.findNoteBy({ id })
          : store.findNoteBy({ id, orgId: session.orgId });
      if (!note) notFound(id);
      return ok(note);
    }),
  );

  // ── S9: note_share_prepare / note_share_redeem ───────────────────────────
  // AUTHZ-FROM-CLIENT-ROUND-TRIPPED-VALUE BOLA (CWE-639) — the tool-chaining
  // surface.
  //
  // `note_share_prepare` is correctly authorized: it mints an opaque grant
  // for a note the CALLER'S OWN session can already access. `note_share_redeem`
  // decodes the grant and serves whatever `noteId` is inside it — because
  // "the grant must have come from an authorized tool." The grant is a plain
  // client-side string between the two calls; nothing stops the caller from
  // decoding it and editing the id before redeeming.
  //
  //   Exploit: Alice calls note_share_prepare for her own note (n_acme_1),
  //            gets back a base64url grant, decodes it, rewrites the noteId
  //            field to n_globex_1, re-encodes it, and calls
  //            note_share_redeem with the tampered grant.
  //
  // In an MCP server there is no server-side continuity between two
  // `tools/call` invocations — every value that crosses that gap travels
  // through the client, and in an agentic loop through the MODEL'S CONTEXT.
  // "A prior tool already checked this" is a client-side claim, not a server
  // fact. Even a SIGNED grant is not enough on its own if the redeeming tool
  // trusts the signed payload instead of re-checking it against the current
  // session: the authority has to live in the session, not in the token.
  server.registerTool(
    "note_share_prepare",
    {
      description:
        "Prepare an opaque share grant for one of your own notes, redeemable via note_share_redeem.",
      inputSchema: { token: z.string(), id: z.string() },
    },
    guard(async ({ token, id }) => {
      const session = resolveSession(store, token);
      const note = store.getNote(id);
      if (!note) notFound(id);
      requireOrgAccess(session, note); // correctly authorized — prepare is not the bug
      const grant = Buffer.from(JSON.stringify({ noteId: note.id })).toString(
        "base64url",
      );
      return ok({ grant });
    }),
  );

  server.registerTool(
    "note_share_redeem",
    {
      description: "Redeem an opaque share grant produced by note_share_prepare.",
      inputSchema: { token: z.string(), grant: z.string() },
    },
    guard(async ({ token, grant }) => {
      const session = resolveSession(store, token);
      const decoded = JSON.parse(
        Buffer.from(grant, "base64url").toString("utf8"),
      );
      // S9 vuln:  the decoded grant IS the authorization.
      // S9 fixed: the grant is a hint; the session is re-checked as authority.
      if (modes.s9 === "vuln") {
        const note = store.getNote(decoded.noteId);
        if (!note) notFound(decoded.noteId);
        return ok(note);
      }
      const note = store.getNote(decoded.noteId);
      if (!note) notFound(decoded.noteId);
      requireOrgAccess(session, note); // <-- THE FIX
      return ok(note);
    }),
  );

  // ── S8: note://{token}/{orgId}/{noteId} resource ─────────────────────────
  // RESOURCE-URI-AS-SCOPE BOLA (CWE-639) — the resources/read surface.
  //
  // `resources/*` is a separate MCP primitive from `tools/*`: its own
  // registration API (registerResource + ResourceTemplate), its own handler
  // signature ((uri, variables) instead of a single args object), and its own
  // client flow (resources/read, not tools/call). "Read every tool" habits
  // never look here.
  //
  // The URI template turns the tenant into a path segment the CALLER writes.
  // In vuln mode the handler trusts that segment as the scope; in fixed mode
  // it is ignored and the session's own org is used instead. Identity still
  // travels in the URI (`{token}`) — that is deliberate, the same per-call
  // token model every tool in this lab uses (see src/auth.js) — only the
  // SCOPE segment is the planted bug.
  //
  //   Exploit: Alice (alice-token, org Acme) reads
  //            note://alice-token/org_globex/n_globex_1 → in vuln mode the
  //            orgId path segment is trusted and Globex's note is returned.
  server.registerResource(
    "note",
    new ResourceTemplate("note://{token}/{orgId}/{noteId}", {
      list: undefined,
    }),
    {
      title: "Note",
      description: "Read a single note as an MCP resource.",
    },
    async (uri, { token, orgId, noteId }) => {
      const session = resolveSession(store, token);
      // S8 vuln:  scope comes from the URI segment the caller wrote.
      // S8 fixed: scope comes from the session; the URI segment is ignored.
      const scope = modes.s8 === "vuln" ? orgId : session.orgId;
      const note = store.findNoteBy({ id: noteId, orgId: scope });
      if (!note) notFound(noteId);
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(note, null, 2),
          },
        ],
      };
    },
  );

  // ── S10: note_get_scoped ──────────────────────────────────────────────────
  // FORWARDED-HEADER-AS-SCOPE BOLA (CWE-639 / CWE-290) — the transport surface.
  //
  // Every prior scenario reads its scope from a tool ARGUMENT (S1-S7, S9) or a
  // resource URI (S8). This one reads it from an HTTP REQUEST HEADER. When an
  // MCP server runs over the streamable-HTTP transport, each tool call carries
  // the underlying request's headers in `extra.requestInfo.headers`. A server
  // deployed behind a gateway/proxy is tempted to trust an identity or routing
  // header — `X-Org-Id` here, `X-Forwarded-For` in the IP-scoping variant — as
  // the authorization scope. But that header is entirely client-controlled: any
  // caller can set it. This is the transport-layer sibling of S2's
  // scope-as-param, and it is exactly the real-world "trusting X-Forwarded-For
  // for a security decision" class.
  //
  //   Exploit: Alice (org_acme) calls note_get_scoped over HTTP with header
  //            `X-Org-Id: org_globex` → she reads Globex's notes.
  //
  // Over the stdio transport there is no requestInfo, so `headerOrg` is
  // undefined and the tool falls back to the session — the bug only manifests
  // over HTTP, which is precisely why a stdio-only review never sees it.
  //
  // In fixed mode the header is ignored; session.orgId (server-trusted) is
  // always used.
  server.registerTool(
    "note_get_scoped",
    {
      description:
        "List the caller's notes. Honors an X-Org-Id routing header set by the API gateway.",
      inputSchema: {
        token: z.string(),
      },
    },
    guard(async ({ token }, extra) => {
      const session = resolveSession(store, token);
      // S10 vuln: trust the client-supplied X-Org-Id header as the scope.
      // S10 fixed: ignore the header; always use session.orgId.
      const headerOrg = extra?.requestInfo?.headers?.["x-org-id"];
      const effectiveOrgId =
        modes.s10 === "vuln" && headerOrg ? headerOrg : session.orgId;
      return ok(store.listNotesByOrg(effectiveOrgId));
    }),
  );

  // ── S11: note_create_limited ───────────────────────────────────────────────
  // X-FORWARDED-FOR QUOTA/RATE-LIMIT BYPASS (CWE-639 / CWE-290) — the quota
  // sibling of S10. HTTP-only (stdio has no headers, like S10).
  //
  // The tool enforces a per-client creation quota. In vuln mode the quota key
  // is the X-Forwarded-For header — any caller can spoof it to reset their
  // quota and create unlimited notes. In fixed mode the quota is keyed to the
  // server-trusted session (token), so spoofing XFF has no effect.
  //
  // Real-world source: audit found SurfSense rate_limiter.py using XFF as the
  // client identity for rate limiting → spoofed XFF bypasses the limit.
  server.registerTool(
    "note_create_limited",
    {
      description:
        "Create a note with a per-client quota (max 3 notes). The quota is tracked by client identity.",
      inputSchema: {
        token: z.string(),
        title: z.string(),
        body: z.string().optional(),
      },
    },
    guard(async ({ token, title, body }, extra) => {
      const session = resolveSession(store, token);
      // S11 vuln: quota keyed on X-Forwarded-For header (client-controlled).
      // S11 fixed: quota keyed on session (server-trusted).
      // Test-only: allow x-test-xff header to override x-forwarded-for for PoC testing
      const testXff = extra?.requestInfo?.headers?.["x-test-xff"];
      const xff = testXff ?? extra?.requestInfo?.headers?.["x-forwarded-for"];
      const quotaKey =
        modes.s11 === "vuln"
          ? xff ?? session.orgId
          : session.userId;
      const currentCount = store.getQuotaCount(quotaKey);
      if (currentCount >= 3) {
        return fail(
          `Quota exceeded for ${quotaKey}. Maximum 3 notes per client.`,
        );
      }
      const note = store.createNote({
        orgId: session.orgId,
        ownerId: session.userId,
        title,
        body,
      });
      store.incrementQuota(quotaKey);
      return ok(note);
    }),
  );

  // ── S12: note_batch_resolve ──────────────────────────────────────────────────
  // BATCH/BULK ENDPOINT BOLA (CWE-639 / CWE-862) — multi-object endpoint without per-item tenant filter.
  //
  // Completes the single-object scenarios (S1-S7) by showing the same bug at batch scale.
  // A list/batch endpoint returns multiple objects by id, but skips the per-item org check.
  // An attacker who knows ids from another org can include them in the batch and receive them.
  // This is the "list→get asymmetry" pattern at batch scale — very common in real MCP servers.
  //
  //   Exploit: Alice (org Acme) calls note_batch_resolve with ids ["n_acme_1", "n_globex_1"]
  //            In vuln mode both are returned; she reads Globex's note.
  //
  // In fixed mode resolved notes are filtered to session.orgId before returning.
  server.registerTool(
    "note_batch_resolve",
    {
      description:
        "Fetch multiple notes by id in a single batch call (up to 50 ids). Returns all requested notes.",
      inputSchema: {
        token: z.string(),
        ids: z.array(z.string()).min(1).max(50),
      },
    },
    guard(async ({ token, ids }) => {
      const session = resolveSession(store, token);
      const resolved = ids.map((id) => store.getNote(id)).filter(Boolean);
      // S12 vuln: return all resolved notes with no per-item org check.
      // S12 fixed: filter each resolved note to caller's org before returning.
      const result =
        modes.s12 === "vuln"
          ? resolved
          : resolved.filter((n) => n.orgId === session.orgId);
      return ok(result);
    }),
  );

  // ── S13: note_get_by_token_scope ──────────────────────────────────────────────
  // JWT/TOKEN SCOPE CONFUSION (CWE-639 / CWE-290) — scope claim in token vs actual permissions mismatch.
  //
  // MCP auth layer trusts a scope/aud claim inside the token (JWT or opaque) to select tenant scope,
  // but the token's scope claim may not match the caller's actual permissions (scope confusion).
  // This is MCP-specific: the token is presented per-call, and a malicious or misconfigured client
  // can present a token with an inflated scope claim that the server trusts without re-verifying
  // against the session/identity provider.
  //
  //   Exploit: Alice (org Acme) presents a token with scope="org_globex" (or aud="org_globex")
  //            In vuln mode the server trusts the token's scope claim and returns Globex's notes.
  //
  // In fixed mode the server derives scope from the resolved session (server-trusted), ignoring
  // any scope/aud claim carried in the token itself. The token authenticates *who you are*; the
  // session determines *what you may access*.
  server.registerTool(
    "note_get_by_token_scope",
    {
      description:
        "Get notes for the organization indicated by the token's scope claim. The token carries the intended scope.",
      inputSchema: {
        token: z.string(),
        scope: z.string().optional().describe("Optional scope override from token claims (aud/scope)"),
      },
    },
    guard(async ({ token, scope }) => {
      const session = resolveSession(store, token);
      // S13 vuln: trust the caller-supplied scope claim (from token's aud/scope) as the authorization scope.
      // S13 fixed: always use session.orgId (server-trusted); ignore token's scope claim.
      const effectiveOrgId =
        modes.s13 === "vuln" && scope ? scope : session.orgId;
      return ok(store.listNotesByOrg(effectiveOrgId));
    }),
  );
}
