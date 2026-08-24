// Test fixture for rule: mcp-client-supplied-scope-overrides-session-rust
//
// The JS/Python sibling rules match a fallback EXPRESSION
// (`org_id || session.orgId`, `org_id or session.org_id`). rmcp handler
// arguments are plain (non-Option) fields destructured from `Parameters<T>`,
// so there is no idiomatic Rust fallback/coalesce spelling of the same
// defect -- a caller either supplies org_id or does not have the field at
// all. This fixture instead carries the shape the wave brief itself
// specifies: the client-destructured org_id field reaching the sink
// directly, in place of the session's own field.
//
// The "ok_intermediate_named_scope" case is the required negative from the
// brief: a local variable named `scope` (not `org_id`) holds the
// session-derived value. It stays silent for the same reason
// `ok_session_field` does -- the anchored name regex only binds identifiers
// literally spelled `org_id`/`tenant_id`/etc, so a differently-named local
// or a `session.org_id` field access never matches $SCOPEPARAM's text.
//
// Known limitation (measured, not fixed here): a local variable that is
// BOTH session-derived AND happens to be named `org_id`
// (`let org_id = session.org_id.clone(); store.find_note_by(id, &org_id)`)
// still matches -- the rule tracks the identifier's name, not its origin.
// Taint mode resolves this ambiguity correctly (verified in this wave's
// canary run), but the house style here is pattern-based (0 of 12 existing
// rules use `mode: taint`), so this is a documented, deliberate trade-off
// rather than a miss.

use rmcp::{tool, tool_router};

struct FindParams {
    token: String,
    note_id: String,
    org_id: String,
}

struct Note {
    id: String,
}

struct Store;

impl Store {
    fn find_note_by(&self, id: &str, org: &str) -> Note {
        Note { id: id.to_string() }
    }
}

struct Session {
    org_id: String,
}

fn resolve_session(store: &Store, token: &str) -> Session {
    Session { org_id: String::new() }
}

struct NoteTools {
    store: Store,
    session: Session,
}

#[tool_router]
impl NoteTools {
    #[tool(description = "Find a note by id, scoped by client-supplied org")]
    async fn note_find_vuln(
        &self,
        Parameters(FindParams { token, note_id, org_id }): Parameters<FindParams>,
    ) -> String {
        let session = resolve_session(&self.store, &token);
        // ruleid: mcp-client-supplied-scope-overrides-session-rust
        let note = self.store.find_note_by(&note_id, &org_id);
        note.id
    }

    #[tool(description = "Find a note by id, scoped by session org")]
    async fn note_find_session_scoped(
        &self,
        Parameters(FindParams { token, note_id, org_id }): Parameters<FindParams>,
    ) -> String {
        let session = resolve_session(&self.store, &token);
        // ok: mcp-client-supplied-scope-overrides-session-rust
        let note = self.store.find_note_by(&note_id, &session.org_id);
        note.id
    }

    #[tool(description = "Find a note by id, session scope copied to a differently-named local")]
    async fn note_find_intermediate_named_scope(
        &self,
        Parameters(FindParams { token, note_id, org_id }): Parameters<FindParams>,
    ) -> String {
        let session = resolve_session(&self.store, &token);
        let scope = session.org_id.clone();
        // ok: mcp-client-supplied-scope-overrides-session-rust
        let note = self.store.find_note_by(&note_id, &scope);
        note.id
    }
}
