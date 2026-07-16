// Unit tests for src/auth.js — the pure identity + authorization checks.
//
// These exercise resolveSession()/requireOrgAccess()/requireAdminRole()
// directly, independent of the MCP transport. The PoC (poc/exploit.js)
// proves the tools wire these checks correctly end-to-end; these tests
// prove the checks themselves are correct in isolation, including the
// edge cases (missing token, missing object, missing session) that the
// PoC's happy-path scenarios don't exercise.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createStore } from "../src/store.js";
import {
  resolveSession,
  requireOrgAccess,
  requireAdminRole,
  AuthnError,
  AuthzError,
} from "../src/auth.js";

// ── resolveSession() ────────────────────────────────────────────────────

test("resolveSession: valid token resolves the correct user/org/role", () => {
  const store = createStore();
  const session = resolveSession(store, "alice-token");
  assert.equal(session.userId, "u_alice");
  assert.equal(session.userName, "Alice");
  assert.equal(session.orgId, "org_acme");
  assert.equal(session.orgName, "Acme");
  assert.equal(session.role, "user");
});

test("resolveSession: Dana's token resolves role 'admin'", () => {
  const store = createStore();
  const session = resolveSession(store, "dana-token");
  assert.equal(session.userId, "u_dana");
  assert.equal(session.orgId, "org_platform");
  assert.equal(session.role, "admin");
});

test("resolveSession: each of the three tenant tokens resolves its own org", () => {
  const store = createStore();
  assert.equal(resolveSession(store, "alice-token").orgId, "org_acme");
  assert.equal(resolveSession(store, "bob-token").orgId, "org_globex");
  assert.equal(resolveSession(store, "carol-token").orgId, "org_initech");
});

test("resolveSession: unknown token throws AuthnError", () => {
  const store = createStore();
  assert.throws(() => resolveSession(store, "not-a-real-token"), AuthnError);
});

test("resolveSession: missing/undefined token throws AuthnError", () => {
  const store = createStore();
  assert.throws(() => resolveSession(store, undefined), AuthnError);
});

test("resolveSession: empty-string token throws AuthnError", () => {
  const store = createStore();
  assert.throws(() => resolveSession(store, ""), AuthnError);
});

// ── requireOrgAccess() ──────────────────────────────────────────────────

test("requireOrgAccess: same-org object does not throw", () => {
  const session = { orgId: "org_acme" };
  const note = { orgId: "org_acme", title: "own note" };
  assert.doesNotThrow(() => requireOrgAccess(session, note));
});

test("requireOrgAccess: cross-org object throws AuthzError", () => {
  const session = { orgId: "org_acme" };
  const foreignNote = { orgId: "org_globex", title: "not yours" };
  assert.throws(() => requireOrgAccess(session, foreignNote), AuthzError);
});

test("requireOrgAccess: null object throws AuthzError (not-found should be checked first by callers)", () => {
  const session = { orgId: "org_acme" };
  assert.throws(() => requireOrgAccess(session, null), AuthzError);
});

test("requireOrgAccess: undefined object throws AuthzError", () => {
  const session = { orgId: "org_acme" };
  assert.throws(() => requireOrgAccess(session, undefined), AuthzError);
});

// ── requireAdminRole() ───────────────────────────────────────────────────

test("requireAdminRole: admin session does not throw", () => {
  assert.doesNotThrow(() => requireAdminRole({ role: "admin" }));
});

test("requireAdminRole: ordinary-user session throws AuthzError", () => {
  assert.throws(() => requireAdminRole({ role: "user" }), AuthzError);
});

test("requireAdminRole: null session throws AuthzError", () => {
  assert.throws(() => requireAdminRole(null), AuthzError);
});

test("requireAdminRole: undefined session throws AuthzError", () => {
  assert.throws(() => requireAdminRole(undefined), AuthzError);
});

test("requireAdminRole: error message reports the actual (non-admin) role", () => {
  assert.throws(
    () => requireAdminRole({ role: "user" }),
    /session role is 'user'/,
  );
});

test("requireAdminRole: error message falls back to 'none' for a session with no role", () => {
  assert.throws(() => requireAdminRole({}), /session role is 'none'/);
});
