# Test fixture for rule: mcp-authz-scope-from-request-header-py
#
# S10 (forwarded-header-as-scope), Python/FastMCP spelling. FastMCP exposes the
# underlying HTTP request headers via get_http_headers() (a dict-like). A
# handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
# for IP scoping) as the authorization scope has the same client-controlled
# input as the JS sibling. The legitimate-neighbor reads a non-scope header
# (X-Request-Id) for logging and must stay silent.

from fastmcp.server.dependencies import get_http_headers


# VULN: a scope-shaped header selects whose notes are returned.
def note_get_scoped_vuln(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    # ruleid: mcp-authz-scope-from-request-header-py
    header_org = headers.get("x-org-id")
    effective_org = header_org or session.org_id
    return store.list_notes_by_org(effective_org)


# OK: scope comes from the session; no header is consulted.
def note_get_scoped_fixed(token):
    session = resolve_session(store, token)
    # ok: mcp-authz-scope-from-request-header-py
    return store.list_notes_by_org(session.org_id)


# OK (legitimate neighbor): a non-scope header read for logging only.
def log_request():
    headers = get_http_headers()
    # ok: mcp-authz-scope-from-request-header-py
    req_id = headers.get("x-request-id")
    logger.info("tool invoked", extra={"req_id": req_id})
