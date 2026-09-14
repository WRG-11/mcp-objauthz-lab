// Real-capture false-positive fixture for: mcp-write-parent-from-client-argument
//
// Captured from a danny-avila/LibreChat scan (2026-09-14). The write's tenant key
// is derived SERVER-side -- a getter/helper call (getTenantId(), resolveTenantId(req))
// -- not a caller-supplied argument. A caller argument is an identifier or property
// access; a function call computes the scope on the server. Both must stay SILENT.
//
// Hardening: a tenant-key value that is a call expression is excluded. The plain
// `store.createNote({ orgId: org_id })` true positive (org_id is an identifier) is
// unaffected -- see write-parent-from-client-argument.js.
//
// Known limitation (unchanged, WARNING-level): a tenant key bound from a bare local
// variable is textually identical to a client argument and still flags; the
// variable's origin cannot be decided from one call site.

async function identityContextFromServerHelper(req) {
  // ok: mcp-write-parent-from-client-argument
  return identityStore.createContext({ tenantId: getTenantId(), userId: req.user.id });
}

async function sessionIdentityFromRequest(req, userId) {
  // ok: mcp-write-parent-from-client-argument
  return identityStore.createSessionIdentity({ tenantId: resolveTenantId(req), userId });
}
