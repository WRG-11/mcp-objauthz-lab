# Test fixture for rule: mcp-batch-resolve-missing-per-item-scope-filter-py
#
# S12 (batch/bulk endpoint BOLA). Python spelling: list comprehension
# resolving multiple ids without per-item scope filter.

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