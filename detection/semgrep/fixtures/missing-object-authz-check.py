# Test fixture for rule: mcp-missing-object-authz-check
#
# The guarded case uses `require_org_access`, not `requireOrgAccess`. That is
# the whole point: a Python author writes snake_case, and before the exemption
# list learned those names this correctly-guarded handler was reported as
# vulnerable. A gate wider than its defect gets switched off.


async def vuln_delete(store, token, note_id):
    session = resolve_session(store, token)
    note = store.get_note(note_id)
    # ruleid: mcp-missing-object-authz-check
    store.delete_note(note.id)
    return ok({"deleted": note.id})


async def fixed_delete_snake_case_guard(store, token, note_id):
    session = resolve_session(store, token)
    note = store.get_note(note_id)
    require_org_access(session, note)
    # ok: mcp-missing-object-authz-check
    store.delete_note(note.id)
    return ok({"deleted": note.id})


async def fixed_delete_camel_case_guard(store, token, note_id):
    """A Python codebase calling into a JS-named helper is unusual but legal."""
    session = resolve_session(store, token)
    note = store.get_note(note_id)
    requireOrgAccess(session, note)
    # ok: mcp-missing-object-authz-check
    store.delete_note(note.id)
    return ok({"deleted": note.id})
