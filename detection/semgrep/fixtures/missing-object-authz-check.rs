// Test fixture for rule: mcp-missing-object-authz-check-rust
//
// Rust port of missing-object-authz-check.{js,py}. The fetch and mutation
// use the real rmcp handler shape: arguments arrive wrapped in
// `Parameters<T>` and are destructured in the function signature
// (`Parameters(DeleteParams { token, note_id }): Parameters<DeleteParams>`),
// not as individual named parameters.

use rmcp::{tool, tool_router};

struct DeleteParams {
    token: String,
    note_id: String,
}

struct Note {
    id: String,
}

struct Store;

impl Store {
    fn get_note(&self, id: &str) -> Note {
        Note { id: id.to_string() }
    }
    fn delete_note(&self, id: &str) {}
}

struct Session;

fn resolve_session(store: &Store, token: &str) -> Session {
    Session
}

fn require_org_access(session: &Session, note: &Note) {}

struct NoteTools {
    store: Store,
}

#[tool_router]
impl NoteTools {
    #[tool(description = "Delete a note")]
    async fn note_delete(
        &self,
        Parameters(DeleteParams { token, note_id }): Parameters<DeleteParams>,
    ) -> String {
        let session = resolve_session(&self.store, &token);
        let note = self.store.get_note(&note_id);
        // ruleid: mcp-missing-object-authz-check-rust
        self.store.delete_note(&note.id);
        note.id
    }

    #[tool(description = "Delete a note, org-checked")]
    async fn note_delete_checked(
        &self,
        Parameters(DeleteParams { token, note_id }): Parameters<DeleteParams>,
    ) -> String {
        let session = resolve_session(&self.store, &token);
        let note = self.store.get_note(&note_id);
        require_org_access(&session, &note);
        // ok: mcp-missing-object-authz-check-rust
        self.store.delete_note(&note.id);
        note.id
    }
}
