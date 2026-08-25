// Test fixture for rule: mcp-client-supplied-scope-overrides-session (S13)
//
// S13 (JWT/token scope confusion). The token's scope/aud claim (or a parameter
// mirroring it) is trusted as the authorization scope, overriding the
// server-trusted session. This is the same pattern as S2 (scope-as-param)
// but the scope parameter name is "scope" or "aud" instead of "org_id"/"tenant_id".
//
// Two-way canary axis: does the code use the caller-supplied scope/aud to
// override the session? (yes ⇒ FIRE; no ⇒ SILENT)

async function getNotesByTokenScopeVuln({ token, scope }) {
  const session = resolveSession(token);
  // ruleid: mcp-client-supplied-scope-overrides-session
  const effectiveOrgId = scope ?? session.orgId;
  return store.listNotesByOrg(effectiveOrgId);
}

async function getNotesByTokenScopeVuln2({ token, aud }) {
  const session = resolveSession(token);
  // ruleid: mcp-client-supplied-scope-overrides-session
  const effectiveOrgId = aud || session.orgId;
  return store.listNotesByOrg(effectiveOrgId);
}

async function getNotesByTokenScopeSafe({ token, scope }) {
  const session = resolveSession(token);
  // ok: mcp-client-supplied-scope-overrides-session
  return store.listNotesByOrg(session.orgId);
}

async function getNotesByTokenScopeSafe2({ token, aud }) {
  const session = resolveSession(token);
  // ok: mcp-client-supplied-scope-overrides-session
  return store.listNotesByOrg(session.orgId);
}