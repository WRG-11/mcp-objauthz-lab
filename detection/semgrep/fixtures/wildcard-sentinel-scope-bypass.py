# Test fixture for rule: mcp-wildcard-sentinel-scope-bypass
#
# `==` is JavaScript's secondary equality operator but Python's ONLY one, so
# this rule needed a name filter before it could target Python. Measured on a
# real 215-file Python MCP server: two findings, both a tokenizer comparing
# `ch == "*"`, both false.
#
# The rule REQUIRES the wildcard comparison to be in an AUTHORIZATION BYPASS
# CONTEXT (it gates scope widening, returns all tenants' data). A textual "*"
# or "all" comparison in markup rendering, UI filters, tokenizers, or logging
# is NOT an authz decision and must stay silent.
#
# TWO-WAY CANARY:
# - FIRE: wildcard in authz bypass context (gates scope widening, returns all orgs' data)
# - SILENT: wildcard in non-authz context (markup, UI filter, tokenizer, logging)


async def vuln_export(store, token, org_id):
    session = resolve_session(store, token)
    # ruleid: mcp-wildcard-sentinel-scope-bypass
    if org_id == "*" or org_id == "all":
        return ok(store.list_all_notes())
    return ok(store.list_notes_by_org(session.org_id))


async def vuln_export_ternary(store, token, org_id):
    session = resolve_session(store, token)
    # ruleid: mcp-wildcard-sentinel-scope-bypass
    return ok(store.list_all_notes() if org_id == "*" else store.list_notes_by_org(session.org_id))


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


def render_markdown(text):
    """Markup rendering -- wildcard is textual syntax, not authz scope."""
    # ok: mcp-wildcard-sentinel-scope-bypass
    return text.replace(r"\*(.+?)\*", "<b>\\1</b>")


def filter_notes_by_scope(notes, scope):
    """UI search filter -- 'all' is a display filter, not an authz bypass."""
    # ok: mcp-wildcard-sentinel-scope-bypass
    if scope == "all":
        return notes
    return [n for n in notes if n.scope == scope]


def log_scope_value(scope):
    """Logging -- wildcard comparison for audit, not authz decision."""
    # ok: mcp-wildcard-sentinel-scope-bypass
    if scope == "*":
        logger.info("wildcard scope requested")