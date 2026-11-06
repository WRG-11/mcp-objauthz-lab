# Test fixture for rule: mcp-batch-resolve-missing-per-item-scope-filter-py
#
# S12 (batch/bulk endpoint BOLA). Python spelling: list comprehension
# resolving multiple ids without per-item scope filter.

from notes import get_note_title

def batch_resolve_vuln(ids):
    # ruleid: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [store.get_note(f) for f in ids]

def batch_resolve_safe(ids, session):
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    resolved = [store.get_note(f) for f in ids]
    return [n for n in resolved if n.org_id == session.org_id]

def batch_resolve_with_filter(ids, session):
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    resolved = [store.get_note(f) for f in ids]
    return [n for n in resolved if n.org_id == session.org_id]

def batch_resolve_assigned_unfiltered(ids):
    # ruleid: mcp-batch-resolve-missing-per-item-scope-filter-py
    resolved = [store.get_note(f) for f in ids]
    return resolved

def batch_resolve_nested_filter(ids, session):
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [n for n in [store.get_note(f) for f in ids] if n.org_id == session.org_id]

def batch_resolve_typed(ids: list[str]):
    # ruleid: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [store.get_note(i) for i in ids]

async def batch_resolve_args_field(args):
    # ruleid: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [store.get_note(i) for i in args.ids]

def batch_resolve_server_derived(session):
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    ids = store.list_note_ids(session.org_id)
    return [store.get_note(i) for i in ids]

def batch_titles_via_imported_function(ids):
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [get_note_title(i) for i in ids]

def batch_resolve_session_field(token):
    session = resolve_session(store, token)
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    return [store.get_note(i) for i in session.pinned_note_ids]
