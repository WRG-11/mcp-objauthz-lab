// Unit tests for src/store.js — the in-memory multi-tenant data layer.
//
// createStore() returns a fresh, independent Map-backed store on every
// call, so each test below calls it directly rather than sharing a
// fixture — that keeps mutation tests (create/update/delete) from leaking
// state into unrelated tests.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createStore } from "../src/store.js";

// ── getOrg() / getUser() ─────────────────────────────────────────────────

test("getOrg: returns the known seed orgs", () => {
  const store = createStore();
  assert.equal(store.getOrg("org_acme").name, "Acme");
  assert.equal(store.getOrg("org_platform").name, "Platform Ops");
});

test("getOrg: unknown id returns undefined", () => {
  const store = createStore();
  assert.equal(store.getOrg("org_nope"), undefined);
});

test("getUser: returns the known seed users, including admin Dana", () => {
  const store = createStore();
  assert.equal(store.getUser("u_alice").orgId, "org_acme");
  assert.equal(store.getUser("u_dana").role, "admin");
});

test("getUser: unknown id returns undefined", () => {
  const store = createStore();
  assert.equal(store.getUser("u_nope"), undefined);
});

// ── listNotesByOrg() / listAllNotes() / getNote() ────────────────────────

test("listNotesByOrg: returns exactly the caller org's notes, none other", () => {
  const store = createStore();
  const acme = store.listNotesByOrg("org_acme");
  assert.equal(acme.length, 2);
  assert.ok(acme.every((n) => n.orgId === "org_acme"));
});

test("listNotesByOrg: an org with no notes (Platform Ops) returns an empty array", () => {
  const store = createStore();
  assert.deepEqual(store.listNotesByOrg("org_platform"), []);
});

test("listNotesByOrg: unknown org id returns an empty array, not undefined", () => {
  const store = createStore();
  assert.deepEqual(store.listNotesByOrg("org_nope"), []);
});

test("listAllNotes: returns all six seed notes across all three tenants", () => {
  const store = createStore();
  const all = store.listAllNotes();
  assert.equal(all.length, 6);
  const orgs = new Set(all.map((n) => n.orgId));
  assert.deepEqual(orgs, new Set(["org_acme", "org_globex", "org_initech"]));
});

test("getNote: known id returns the note, unknown id returns undefined", () => {
  const store = createStore();
  assert.equal(store.getNote("n_acme_1").title, "Acme acquisition memo");
  assert.equal(store.getNote("n_nope"), undefined);
});

// ── createNote() ──────────────────────────────────────────────────────────

test("createNote: assigns a fresh id and is retrievable via getNote", () => {
  const store = createStore();
  const note = store.createNote({
    orgId: "org_acme", ownerId: "u_alice", title: "new note", body: "hi",
  });
  assert.ok(note.id.startsWith("n_"));
  assert.deepEqual(store.getNote(note.id), note);
});

test("createNote: sequential ids never collide across repeated calls", () => {
  const store = createStore();
  const a = store.createNote({ orgId: "org_acme", ownerId: "u_alice", title: "a" });
  const b = store.createNote({ orgId: "org_acme", ownerId: "u_alice", title: "b" });
  assert.notEqual(a.id, b.id);
});

test("createNote: omitted body defaults to an empty string, not undefined", () => {
  const store = createStore();
  const note = store.createNote({ orgId: "org_acme", ownerId: "u_alice", title: "no body" });
  assert.equal(note.body, "");
});

test("createNote: a note created for one org never appears in another org's list", () => {
  const store = createStore();
  store.createNote({ orgId: "org_globex", ownerId: "u_bob", title: "globex-only" });
  const acmeTitles = store.listNotesByOrg("org_acme").map((n) => n.title);
  assert.ok(!acmeTitles.includes("globex-only"));
});

// ── updateNote() ────────────────────────────────────────────────────────

test("updateNote: updates title only, leaves body untouched", () => {
  const store = createStore();
  const before = store.getNote("n_acme_1").body;
  const updated = store.updateNote("n_acme_1", { title: "renamed" });
  assert.equal(updated.title, "renamed");
  assert.equal(updated.body, before);
});

test("updateNote: updates body only, leaves title untouched", () => {
  const store = createStore();
  const before = store.getNote("n_acme_1").title;
  const updated = store.updateNote("n_acme_1", { body: "new body" });
  assert.equal(updated.body, "new body");
  assert.equal(updated.title, before);
});

test("updateNote: unknown id returns undefined and creates nothing", () => {
  const store = createStore();
  assert.equal(store.updateNote("n_nope", { title: "x" }), undefined);
});

test("updateNote: non-string patch values are ignored (type guard holds)", () => {
  const store = createStore();
  const before = store.getNote("n_acme_1").title;
  // @ts-expect-error deliberately wrong type to probe the typeof guard
  const updated = store.updateNote("n_acme_1", { title: 12345 });
  assert.equal(updated.title, before);
});

// ── deleteNote() ────────────────────────────────────────────────────────

test("deleteNote: removes the note; getNote afterward returns undefined", () => {
  const store = createStore();
  assert.equal(store.deleteNote("n_acme_1"), true);
  assert.equal(store.getNote("n_acme_1"), undefined);
});

test("deleteNote: unknown id returns false and does not throw", () => {
  const store = createStore();
  assert.equal(store.deleteNote("n_nope"), false);
});

// ── searchNotesByOrg() ────────────────────────────────────────────────────

test("searchNotesByOrg: matches are case-insensitive on both title and body", () => {
  const store = createStore();
  const byTitle = store.searchNotesByOrg("org_acme", "ACQUISITION");
  assert.equal(byTitle.length, 1);
  const byBody = store.searchNotesByOrg("org_acme", "confidential");
  assert.equal(byBody.length, 1);
});

test("searchNotesByOrg: is scoped to the given org — no cross-tenant leakage", () => {
  const store = createStore();
  // "confidential" appears in every tenant's private note; scoping must hold.
  const acmeResults = store.searchNotesByOrg("org_acme", "confidential");
  assert.ok(acmeResults.every((n) => n.orgId === "org_acme"));
});

test("searchNotesByOrg: empty query returns every note in the org (substring of everything)", () => {
  const store = createStore();
  assert.equal(store.searchNotesByOrg("org_acme", "").length, 2);
});

test("searchNotesByOrg: no match returns an empty array", () => {
  const store = createStore();
  assert.deepEqual(store.searchNotesByOrg("org_acme", "nonexistent-term-xyz"), []);
});
