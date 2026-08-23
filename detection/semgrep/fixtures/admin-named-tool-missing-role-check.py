# Test fixture for rule: mcp-admin-named-tool-missing-role-check-py
#
# Python port of admin-named-tool-missing-role-check.js. The JS rule is
# written against server.registerTool(...) with an arrow-function handler,
# which cannot match Python; FastMCP registers tools as decorated functions.
# Same defect, different registration syntax: the name documents admin-only,
# and only a role check in the body enforces it.


@mcp.tool()
# ruleid: mcp-admin-named-tool-missing-role-check-py
async def note_admin_get(token: str, note_id: str):
    session = resolve_session(store, token)
    note = store.get_note(note_id)
    return ok(note)


@mcp.tool()
# ok: mcp-admin-named-tool-missing-role-check-py
async def note_admin_get_checked(token: str, note_id: str):
    session = resolve_session(store, token)
    require_admin_role(session)
    note = store.get_note(note_id)
    return ok(note)


# A camelCase guard is unusual in Python but legal (a shared helper imported
# from a JS codebase, say) -- and it must count, or the rule's silence would
# be a false negative wearing an ok badge.
@mcp.tool()
# ok: mcp-admin-named-tool-missing-role-check-py
def report_admin_summary(token: str):
    session = resolve_session(store, token)
    requireAdminRole(session)
    return ok(summarize_all_tenants(session))
