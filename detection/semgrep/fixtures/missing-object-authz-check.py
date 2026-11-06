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


# The pure-read spelling, mirrored from the JavaScript fixture: a cross-tenant
# read is the same defect as the mutation, and the rule's read branch covers
# Python identically.
async def vuln_read(store, token, doc_id):
    session = resolve_session(store, token)
    doc = store.get_doc(doc_id)
    # ruleid: mcp-missing-object-authz-check
    return ok(doc)


async def fixed_read(store, token, doc_id):
    session = resolve_session(store, token)
    doc = store.get_doc(doc_id)
    require_ownership(session, doc)
    # ok: mcp-missing-object-authz-check
    return ok(doc)


# The check written inline instead of as a guard call, mirrored from the
# JavaScript fixture.
async def fixed_read_inline(store, token, doc_id):
    session = resolve_session(store, token)
    doc = store.get_doc(doc_id)
    if doc is None or doc.org_id != session.org_id:
        raise NotFound(doc_id)
    # ok: mcp-missing-object-authz-check
    return ok(doc)


async def fixed_delete_inline_reversed(store, token, note_id):
    session = resolve_session(store, token)
    note = store.get_note(note_id)
    if session.org_id != note.org_id:
        raise NotFound(note_id)
    # ok: mcp-missing-object-authz-check
    store.delete_note(note.id)
    return ok({"deleted": note.id})


# VULN: two different keys, as in the JavaScript fixture.
async def vuln_read_wrong_key(store, token, doc_id):
    session = resolve_session(store, token)
    doc = store.get_doc(doc_id)
    if doc is None or doc.org_id != session.user_id:
        raise NotFound(doc_id)
    # ruleid: mcp-missing-object-authz-check
    return ok(doc)
