// Test fixture for rule: mcp-missing-object-authz-check-go
//
// Mirrors missing-object-authz-check.py/.js: an object resolved by a
// client-supplied id reaches a mutation with no ownership/role check in
// between. Go's own spelling — PascalCase exported guards and camelCase
// unexported ones both count, since a Go codebase legitimately uses either.

package fixtures

import "context"

type Note struct {
	ID string
}

type DeleteNoteArgs struct {
	Token  string `json:"token"`
	NoteID string `json:"note_id"`
}

type DeleteOut struct {
	Deleted string `json:"deleted"`
}

type Session struct {
	OrgID string
}

var store *Store

func resolveSession(s *Store, token string) *Session { return nil }
func requireOrgAccess(session *Session, note *Note)   {}
func checkAccess(session *Session, note *Note)        {}
func assertOwner(session *Session, note *Note)        {}

func DeleteNote(ctx context.Context, req *CallToolRequest, args DeleteNoteArgs) (*CallToolResult, DeleteOut, error) {
	session := resolveSession(store, args.Token)
	note := store.GetNote(args.NoteID)
	_ = session
	// ruleid: mcp-missing-object-authz-check-go
	store.DeleteNote(note.ID)
	return nil, DeleteOut{Deleted: note.ID}, nil
}

func DeleteNoteFixedLowerGuard(ctx context.Context, req *CallToolRequest, args DeleteNoteArgs) (*CallToolResult, DeleteOut, error) {
	session := resolveSession(store, args.Token)
	note := store.GetNote(args.NoteID)
	requireOrgAccess(session, note)
	// ok: mcp-missing-object-authz-check-go
	store.DeleteNote(note.ID)
	return nil, DeleteOut{Deleted: note.ID}, nil
}

func DeleteNoteFixedUpperGuard(ctx context.Context, req *CallToolRequest, args DeleteNoteArgs) (*CallToolResult, DeleteOut, error) {
	session := resolveSession(store, args.Token)
	note := store.GetNote(args.NoteID)
	RequireOrgAccess(session, note)
	// ok: mcp-missing-object-authz-check-go
	store.DeleteNote(note.ID)
	return nil, DeleteOut{Deleted: note.ID}, nil
}

// Exported/unexported spellings of the other two guard families in the
// list, so the exemption is proven for all three names, not just one.
func DeleteNoteCheckAccessGuard(ctx context.Context, req *CallToolRequest, args DeleteNoteArgs) (*CallToolResult, DeleteOut, error) {
	session := resolveSession(store, args.Token)
	note := store.GetNote(args.NoteID)
	CheckAccess(session, note)
	// ok: mcp-missing-object-authz-check-go
	store.DeleteNote(note.ID)
	return nil, DeleteOut{Deleted: note.ID}, nil
}

func DeleteNoteAssertOwnerGuard(ctx context.Context, req *CallToolRequest, args DeleteNoteArgs) (*CallToolResult, DeleteOut, error) {
	session := resolveSession(store, args.Token)
	note := store.GetNote(args.NoteID)
	assertOwner(session, note)
	// ok: mcp-missing-object-authz-check-go
	store.DeleteNote(note.ID)
	return nil, DeleteOut{Deleted: note.ID}, nil
}

func RequireOrgAccess(session *Session, note *Note) {}
func CheckAccess(session *Session, note *Note)      {}
