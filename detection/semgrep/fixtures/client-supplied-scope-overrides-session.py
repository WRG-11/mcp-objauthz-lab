# Test fixture for rule: mcp-client-supplied-scope-overrides-session
#
# Python's `or` carries the same trap as JavaScript's `||`: it substitutes only
# on a FALSY left value, so a caller-supplied scope wins whenever it is present
# and the session scope is reached only when the caller omits it.
#
# The write-side spelling at the bottom is the S6 shape. It is covered by this
# rule rather than one of its own -- verified by running the ruleset against
# the lab's real source, where this rule fires on the S6 line in tools.py's
# JavaScript sibling.


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


# The WRITE-side spelling: a caller-supplied parent selects which tenant the
# new object lands in. Poisons another tenant's data instead of leaking it.
async def vuln_create_in_org(store, token, org_id, title, body):
    session = resolve_session(store, token)
    # ruleid: mcp-client-supplied-scope-overrides-session-py-ternary
    target_org_id = org_id if org_id else session.org_id
    return ok(store.create_note(org_id=target_org_id, owner_id=session.user_id,
                                title=title, body=body))


async def fixed_create_in_org(store, token, org_id, title, body):
    """org_id stays in the signature to avoid a breaking API change, and is ignored."""
    session = resolve_session(store, token)
    # ok: mcp-client-supplied-scope-overrides-session-py-ternary
    target_org_id = session.org_id
    return ok(store.create_note(org_id=target_org_id, owner_id=session.user_id,
                                title=title, body=body))
