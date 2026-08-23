# Test fixture for rule: mcp-batch-resolve-missing-per-item-scope-filter-py
#
# Python port of batch-resolve-missing-per-item-scope-filter.js. The JS rule
# matches `ids.map(id => store.getNote(id))`; `.map` with an arrow has no
# Python spelling, and the list comprehension is the idiomatic batch resolve.


def vuln_batch_get(store, token, ids):
    session = resolve_session(store, token)
    # ruleid: mcp-batch-resolve-missing-per-item-scope-filter-py
    resolved = [store.get_note(i) for i in ids]
    return ok(resolved)


def fixed_batch_get(store, token, ids):
    session = resolve_session(store, token)
    resolved = [store.get_note(i) for i in ids]
    # ok: mcp-batch-resolve-missing-per-item-scope-filter-py
    scoped = [n for n in resolved if n.org_id == session.org_id]
    return ok(scoped)
