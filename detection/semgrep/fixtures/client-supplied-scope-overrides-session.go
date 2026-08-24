// Test fixture for rule: mcp-client-supplied-scope-overrides-session-go
//
// Mirrors client-supplied-scope-overrides-session.py/.js, but in Go's own
// idiom: there is no `||`/`??`/ternary, so the override shows up as a
// zero-value fallback (`if scope == "" { scope = session.OrgID }`) instead.
// The legitimate-neighbor canary matters here more than usual — a naive
// "any zero-value fallback" pattern would flag ordinary defaulting
// (`if limit == 0 { limit = 50 }`) and get switched off within a week.

package fixtures

import "context"

type SearchArgs struct {
	Token string `json:"token"`
	Query string `json:"query"`
	OrgID string `json:"org_id"`
}

type SearchOut struct {
	Notes []string
}

type ListArgs struct {
	Limit int `json:"limit"`
}

type ListOut struct {
	Notes []string
}

func SearchNotes(ctx context.Context, req *CallToolRequest, args SearchArgs) (*CallToolResult, SearchOut, error) {
	session := resolveSession(store, args.Token)
	scope := args.OrgID
	if scope == "" {
		scope = session.OrgID
	}
	// ruleid: mcp-client-supplied-scope-overrides-session-go
	return nil, SearchOut{Notes: store.SearchNotesByOrg(scope, args.Query)}, nil
}

func SearchNotesFixed(ctx context.Context, req *CallToolRequest, args SearchArgs) (*CallToolResult, SearchOut, error) {
	session := resolveSession(store, args.Token)
	// ok: mcp-client-supplied-scope-overrides-session-go
	return nil, SearchOut{Notes: store.SearchNotesByOrg(session.OrgID, args.Query)}, nil
}

// Legitimate neighbor: a non-scope field's zero-value fallback must stay
// silent, or the rule fires on every ordinary Go default and gets
// switched off.
func ListRecent(ctx context.Context, req *CallToolRequest, args ListArgs) (*CallToolResult, ListOut, error) {
	limit := args.Limit
	if limit == 0 {
		limit = 50
	}
	// ok: mcp-client-supplied-scope-overrides-session-go
	return nil, ListOut{Notes: store.RecentNotes(limit)}, nil
}
