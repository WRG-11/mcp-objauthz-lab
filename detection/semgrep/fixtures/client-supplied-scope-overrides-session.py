# Test fixture for rule: mcp-client-supplied-scope-overrides-session
#
# Python's `or` carries the same trap as JavaScript's `||`: it substitutes only
# on a FALSY left value, so a caller-supplied scope wins whenever it is present
# and the session scope is reached only when the caller omits it.
#
# The ternary pair at the bottom is Python's OTHER idiomatic override spelling
# (`x if x else y`), covered by mcp-client-supplied-scope-overrides-session-py-
# ternary. It deliberately resolves to a READ sink: the WRITE-side spelling of
# a caller-chosen destination has its own rule and fixture now (see
# write-parent-from-client-argument.py) -- keeping the two apart keeps every
# fixture's count attributable to exactly one rule.


async def vuln_search(store, token, q, org_id):
    session = resolve_session(store, token)
    # ruleid: mcp-client-supplied-scope-overrides-session
    effective_org_id = org_id or session.org_id
    return ok(store.search_notes_by_org(effective_org_id, q))


async def fixed_search(store, token, q, org_id):
    session = resolve_session(store, token)
    # ok: mcp-client-supplied-scope-overrides-session
    effective_org_id = session.org_id
    return ok(store.search_notes_by_org(effective_org_id, q))


# The per-USER spelling. CVE-2026-9135 (IBM Langflow) is this shape verbatim:
# an MCP tool that accepts a caller-supplied user_id and uses it to select
# whose flow to modify.
async def vuln_update_flow_field(store, token, flow_id, field, value, user_id):
    session = resolve_session(store, token)
    # ruleid: mcp-client-supplied-scope-overrides-session
    effective_user_id = user_id or session.user_id
    return ok(store.update_flow_field(effective_user_id, flow_id, field, value))


# The ternary spelling of the override, on a read sink. The caller-supplied
# value wins whenever present -- same defect as `or`, Python's other idiom.
async def vuln_search_ternary(store, token, q, org_id):
    session = resolve_session(store, token)
    # ruleid: mcp-client-supplied-scope-overrides-session-py-ternary
    effective_org_id = org_id if org_id else session.org_id
    return ok(store.search_notes_by_org(effective_org_id, q))


async def fixed_search_ternary(store, token, q, org_id):
    """org_id stays in the signature to avoid a breaking API change, and is ignored."""
    session = resolve_session(store, token)
    # ok: mcp-client-supplied-scope-overrides-session-py-ternary
    effective_org_id = session.org_id
    return ok(store.search_notes_by_org(effective_org_id, q))
