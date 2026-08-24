// Test fixture for rule: mcp-unscoped-query-object-fetch-go
//
// Mirrors unscoped-query-object-fetch.py/.js: an object fetched by id alone
// carries no tenant key. WARNING, not ERROR, same honesty as its siblings —
// a single call site cannot prove the entity is genuinely tenant-scoped.
//
// Honest boundary (see detection/README.md): Go's most common "unscoped
// fetch" shape is a raw SQL string (`db.QueryRow("SELECT ... WHERE id =
// $1", args.NoteID)`), and semgrep cannot reliably see a tenant key inside
// a string literal — that shape is NOT covered here. This rule locks onto
// the statically matchable struct/ORM idiom instead (`db.First(&note, pk)`),
// the Go-idiomatic sibling of the JS `findOneBy`/Python `session.get`
// primary-key lookups already covered.

package fixtures

import "context"

type Note struct {
	ID          string
	WorkspaceID string
}

type GetNoteArgs struct {
	Token  string `json:"token"`
	NoteID string `json:"note_id"`
}

var db *DB

func GetNote(ctx context.Context, req *CallToolRequest, args GetNoteArgs) (*CallToolResult, Note, error) {
	var note Note
	// ruleid: mcp-unscoped-query-object-fetch-go
	db.First(&note, args.NoteID)
	return nil, note, nil
}

func GetNoteFixed(ctx context.Context, req *CallToolRequest, args GetNoteArgs) (*CallToolResult, Note, error) {
	session := resolveSession(store, args.Token)
	var note Note
	// ok: mcp-unscoped-query-object-fetch-go
	db.Where("id = ? AND workspace_id = ?", args.NoteID, session.WorkspaceID).First(&note)
	return nil, note, nil
}
