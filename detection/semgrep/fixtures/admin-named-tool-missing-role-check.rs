// Test fixture for rule: mcp-admin-named-tool-missing-role-check-rust
//
// Rust port of admin-named-tool-missing-role-check.{js,py}. rmcp tools are
// `#[tool]`-annotated async methods on a `#[tool_router]` impl, not
// `server.registerTool(...)` calls or `@mcp.tool()`-decorated free functions
// -- this sibling keys on the async fn name carrying "admin" and the body
// lacking a role check, the same selection axis as the -py sibling.
//
// The `#[tool]` attribute is deliberately not part of the rule's pattern
// (see the rule file's own note); this fixture still carries it on every
// handler because that is what a real rmcp tool looks like, not because the
// rule depends on it.

use rmcp::{tool, tool_router};

struct GetParams {
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
}

struct Session;

fn resolve_session(store: &Store, token: &str) -> Session {
    Session
}

fn require_admin_role(session: &Session) -> Result<(), String> {
    Ok(())
}

struct NoteTools {
    store: Store,
}

#[tool_router]
impl NoteTools {
    #[tool(description = "Admin: read any note across orgs")]
    // ruleid: mcp-admin-named-tool-missing-role-check-rust
    async fn note_admin_get(
        &self,
        Parameters(GetParams { token, note_id }): Parameters<GetParams>,
    ) -> Note {
        let session = resolve_session(&self.store, &token);
        let note = self.store.get_note(&note_id);
        note
    }

    #[tool(description = "Admin: read any note across orgs, role-checked")]
    // ok: mcp-admin-named-tool-missing-role-check-rust
    async fn note_admin_get_checked(
        &self,
        Parameters(GetParams { token, note_id }): Parameters<GetParams>,
    ) -> Note {
        let session = resolve_session(&self.store, &token);
        require_admin_role(&session);
        let note = self.store.get_note(&note_id);
        note
    }
}
