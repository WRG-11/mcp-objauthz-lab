# Test fixture: mcp-resource-uri-variable-used-as-scope-py (S8, FastMCP spelling).

# Vulnerable: the URI template variable org_id is used directly as the scope
# in the store lookup. Whoever writes the URI chooses the tenant.
@mcp.resource("note://{token}/{org_id}/{note_id}")
def read_note(token: str, org_id: str, note_id: str) -> str:
    session = resolve_session(store, token)
    # ruleid: mcp-resource-uri-variable-used-as-scope-py
    return store.find_note_by(id=note_id, org_id=org_id)


# Fixed: the URI still carries org_id (removing it would be a breaking
# template change), but the scope comes from the session instead.
@mcp.resource("note://{token}/{org_id}/{note_id}")
def read_note_fixed(token: str, org_id: str, note_id: str) -> str:
    session = resolve_session(store, token)
    # ok: mcp-resource-uri-variable-used-as-scope-py
    return store.find_note_by(id=note_id, org_id=session.org_id)


# Legitimate sibling: the URI template carries no tenant segment at all —
# only an identity token and the object id.
@mcp.resource("note://{token}/{note_id}")
def read_note_no_tenant_segment(token: str, note_id: str) -> str:
    session = resolve_session(store, token)
    # ok: mcp-resource-uri-variable-used-as-scope-py
    return store.find_note_by(id=note_id, org_id=session.org_id)
