# Test fixture for rule: mcp-authz-scope-from-request-header-py
#
# S10 (forwarded-header-as-scope), Python/FastMCP spelling. FastMCP exposes the
# underlying HTTP request headers via get_http_headers() (a dict-like). A
# handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
# for IP scoping) as the authorization scope has the same client-controlled
# input as the JS sibling. The legitimate-neighbor reads a non-scope header
# (X-Request-Id) for logging and must stay silent.
#
# The rule REQUIRES the header value to reach an AUTHORIZATION DECISION
# (a store/list call that selects tenant scope, or an org_id binding in a query),
# not merely be read into a variable.
#
# TWO-WAY CANARY:
# - FIRE: header value feeds an authz decision (scope/org-id selection, list_notes_by_org(header_value))
# - SILENT: header read ONLY for logging (no authz decision)

from fastmcp.server.dependencies import get_http_headers


# FIRE: header value used to select org scope in a store call (authz decision)
def note_get_scoped_vuln(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    # ruleid: mcp-authz-scope-from-request-header-py
    header_org = headers.get("x-org-id")
    effective_org = header_org or session.org_id
    return store.list_notes_by_org(effective_org)


# FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
def note_get_scoped_by_ip_vuln(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    # ruleid: mcp-authz-scope-from-request-header-py
    fwd = headers.get("x-forwarded-for")
    return store.list_notes_for_client_ip(fwd or session.client_ip)


# FIRE: header used directly as org_id in a query filter (authz decision)
def note_get_by_query_vuln(token, id):
    session = resolve_session(store, token)
    headers = get_http_headers()
    # ruleid: mcp-authz-scope-from-request-header-py
    header_org = headers.get("x-org-id")
    return store.find_note_by({"id": id, "org_id": header_org or session.org_id})


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


# SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
# This is the two-way canary: reading XFF for logging must NOT fire.
def log_client_ip():
    headers = get_http_headers()
    # ok: mcp-authz-scope-from-request-header-py
    client_ip = headers.get("x-forwarded-for")
    logger.info("rate-limit check", extra={"client_ip": client_ip})


# SILENT: scope-shaped header read into a variable but NEVER used for authz
def read_header_but_dont_use(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    # ok: mcp-authz-scope-from-request-header-py
    _unused = headers.get("x-org-id")
    return store.list_notes_by_org(session.org_id)