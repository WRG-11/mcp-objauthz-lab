// Authentication + authorization helpers.
//
// AUTHENTICATION (who are you?) is server-trusted: a bearer token resolves to a
// fixed { user, org } session. The caller does NOT get to assert its own org —
// it only presents a token. (In a real MCP server this identity would come from
// the transport / OAuth layer; here we pass a per-call token to keep the lab a
// single process and to make the authz logic explicit. See README.)
//
// AUTHORIZATION (may you touch THIS object?) is the interesting part and the
// subject of the lab: requireOrgAccess() enforces that an object belongs to the
// caller's org. The bug is a tool that forgets to call it. See src/tools.js.

/** Raised when a token is unknown / the session cannot be established. */
export class AuthnError extends Error {}

/** Raised when the session may not access the requested object. */
export class AuthzError extends Error {}

/** Raised when the requested object id does not exist. */
export class NotFoundError extends Error {}

// token -> the (server-trusted) user it authenticates as.
const TOKENS = new Map([
  ["alice-token", "u_alice"], // Alice, org Acme
  ["bob-token",   "u_bob"],   // Bob, org Globex
  ["carol-token", "u_carol"], // Carol, org Initech
  ["dana-token",  "u_dana"],  // Dana, org Platform Ops — the only real admin
]);

/**
 * Resolve a bearer token to a session. THIS is the trusted identity — the org
 * AND the role come from the user record, never from the caller's input.
 * @returns {{ userId: string, userName: string, orgId: string, orgName: string, role: string }}
 */
export function resolveSession(store, token) {
  const userId = TOKENS.get(token);
  if (!userId) throw new AuthnError("invalid or missing token");
  const user = store.getUser(userId);
  const org  = store.getOrg(user.orgId);
  return {
    userId:   user.id,
    userName: user.name,
    orgId:    org.id,
    orgName:  org.name,
    role:     user.role ?? "user",
  };
}

/**
 * Object-level authorization check: the session may only touch objects that
 * belong to its own org. This is the single check that the planted-bug tool
 * (note_delete, in LAB_MODE=vuln) is missing.
 */
export function requireOrgAccess(session, object) {
  if (!object || object.orgId !== session.orgId) {
    throw new AuthzError(
      `cross-tenant access denied: object belongs to a different org`,
    );
  }
}

/**
 * Role-level authorization check: the session must hold the "admin" role.
 * This is the check the S5 planted-bug tool (note_admin_get, in LAB_S5=vuln)
 * skips entirely — naming a tool "admin_*" is documentation, not enforcement.
 */
export function requireAdminRole(session) {
  if (!session || session.role !== "admin") {
    throw new AuthzError(
      `admin role required: session role is '${session?.role ?? "none"}'`,
    );
  }
}
