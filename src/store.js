// In-memory, multi-tenant data store for the lab.
//
// Three tenants (orgs), each with its own user and a couple of private notes.
// Note ids are short and human-readable on purpose: in the real world,
// object ids are frequently guessable / enumerable, which is what turns a
// missing authorization check into a practical cross-tenant exploit.
//
// Nothing here is sensitive — it is entirely synthetic seed data.

/** @typedef {{ id: string, name: string }} Org */
/** @typedef {{ id: string, orgId: string, name: string }} User */
/** @typedef {{ id: string, orgId: string, ownerId: string, title: string, body: string }} Note */

export function createStore() {
  /** @type {Map<string, Org>} */
  const orgs = new Map([
    ["org_acme",    { id: "org_acme",    name: "Acme" }],
    ["org_globex",  { id: "org_globex",  name: "Globex" }],
    ["org_initech", { id: "org_initech", name: "Initech" }],
  ]);

  /** @type {Map<string, User>} */
  const users = new Map([
    ["u_alice", { id: "u_alice", orgId: "org_acme",    name: "Alice" }],
    ["u_bob",   { id: "u_bob",   orgId: "org_globex",  name: "Bob" }],
    ["u_carol", { id: "u_carol", orgId: "org_initech", name: "Carol" }],
  ]);

  /** @type {Map<string, Note>} */
  const notes = new Map([
    ["n_acme_1", {
      id: "n_acme_1", orgId: "org_acme", ownerId: "u_alice",
      title: "Acme acquisition memo",
      body: "CONFIDENTIAL (Acme only): terms for the pending acquisition.",
    }],
    ["n_acme_2", {
      id: "n_acme_2", orgId: "org_acme", ownerId: "u_alice",
      title: "Acme launch checklist",
      body: "Internal launch steps for the Acme team.",
    }],
    ["n_globex_1", {
      id: "n_globex_1", orgId: "org_globex", ownerId: "u_bob",
      title: "Globex roadmap",
      body: "CONFIDENTIAL (Globex only): the next-quarter roadmap.",
    }],
    ["n_globex_2", {
      id: "n_globex_2", orgId: "org_globex", ownerId: "u_bob",
      title: "Globex vendor list",
      body: "Internal vendor contacts for the Globex team.",
    }],
    ["n_initech_1", {
      id: "n_initech_1", orgId: "org_initech", ownerId: "u_carol",
      title: "Initech TPS reports",
      body: "CONFIDENTIAL (Initech only): Q2 TPS report summary.",
    }],
    ["n_initech_2", {
      id: "n_initech_2", orgId: "org_initech", ownerId: "u_carol",
      title: "Initech budget",
      body: "CONFIDENTIAL (Initech only): the approved annual budget.",
    }],
  ]);

  let seq = 100;

  return {
    getOrg:  (id) => orgs.get(id),
    getUser: (id) => users.get(id),

    listNotesByOrg: (orgId) =>
      [...notes.values()].filter((n) => n.orgId === orgId),

    listAllNotes: () => [...notes.values()],

    getNote: (id) => notes.get(id),

    createNote: ({ orgId, ownerId, title, body }) => {
      const id = `n_${++seq}`;
      const note = { id, orgId, ownerId, title, body: body ?? "" };
      notes.set(id, note);
      return note;
    },

    updateNote: (id, patch) => {
      const note = notes.get(id);
      if (!note) return undefined;
      if (typeof patch.title === "string") note.title = patch.title;
      if (typeof patch.body  === "string") note.body  = patch.body;
      return note;
    },

    deleteNote: (id) => notes.delete(id),

    searchNotesByOrg: (orgId, q) => {
      const needle = (q ?? "").toLowerCase();
      return [...notes.values()].filter(
        (n) =>
          n.orgId === orgId &&
          (n.title.toLowerCase().includes(needle) ||
            n.body.toLowerCase().includes(needle)),
      );
    },
  };
}
