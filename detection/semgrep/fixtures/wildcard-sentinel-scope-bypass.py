# Test fixture for rule: mcp-wildcard-sentinel-scope-bypass
#
# `==` is JavaScript's secondary equality operator but Python's ONLY one, so
# this rule needed a name filter before it could target Python. Measured on a
# real 215-file Python MCP server: two findings, both a tokenizer comparing
# `ch == "*"`, both false.
#
# The last two cases are the negative half of the canary. They compare against
# the same literals and must stay silent -- if a future edit removes the name
# filter, they turn red rather than the rule quietly widening again.


async def vuln_export(store, token, org_id):
    session = resolve_session(store, token)
    # ruleid: mcp-wildcard-sentinel-scope-bypass
    if org_id == "*" or org_id == "all":
        return ok(store.list_all_notes())
    return ok(store.list_notes_by_org(session.org_id))


async def fixed_export(store, token, org_id):
    session = resolve_session(store, token)
    require_admin_role(session)
    # ok: mcp-wildcard-sentinel-scope-bypass
    if org_id == "*" or org_id == "all":
        return ok(store.list_all_notes())
    return ok(store.list_notes_by_org(session.org_id))


def tokenize_javascript(text):
    """Not a scope decision -- a character-level scanner over foreign source."""
    depth = 0
    for i, ch in enumerate(text):
        # ok: mcp-wildcard-sentinel-scope-bypass
        if ch == "*":
            depth += 1
    return depth


def matches_glob(pattern, name):
    """A literal glob comparison on something that is not an authorization scope."""
    # ok: mcp-wildcard-sentinel-scope-bypass
    if pattern == "all":
        return True
    return pattern == name
