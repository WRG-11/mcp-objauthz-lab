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
#
# The rule is a taint rule, so a finding sits on the SINK: the call argument
# that selects the scope. `ruleid:` markers are therefore above the scoping
# call, not above the header read.

from fastmcp.server.dependencies import get_http_headers


# FIRE: header value used to select org scope in a store call (authz decision)
def note_get_scoped_vuln(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    header_org = headers.get("x-org-id")
    effective_org = header_org or session.org_id
    # ruleid: mcp-authz-scope-from-request-header-py
    return store.list_notes_by_org(effective_org)


# FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
def note_get_scoped_by_ip_vuln(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    fwd = headers.get("x-forwarded-for")
    # ruleid: mcp-authz-scope-from-request-header-py
    return store.list_notes_for_client_ip(fwd or session.client_ip)


# FIRE: header used directly as org_id in a query filter (authz decision)
def note_get_by_query_vuln(token, id):
    session = resolve_session(store, token)
    headers = get_http_headers()
    header_org = headers.get("x-org-id")
    # ruleid: mcp-authz-scope-from-request-header-py
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


# FIRE: subscript read, the header picks the tenant.
def project_list_vuln():
    headers = get_http_headers()
    tenant = headers["x-tenant-id"]
    # ruleid: mcp-authz-scope-from-request-header-py
    return store.find_projects(tenant)


# FIRE: the header reaches the scope through a keyword argument.
def workspace_search_vuln(query):
    headers = get_http_headers()
    ws = headers.get("x-workspace-id")
    # ruleid: mcp-authz-scope-from-request-header-py
    return store.search_documents(query, workspace_id=ws)


# OK (legitimate neighbor): a correlation header passed to a list call is not
# a scope. Pins the header-name regex.
def list_by_request_id():
    headers = get_http_headers()
    req_id = headers.get("x-request-id")
    # ok: mcp-authz-scope-from-request-header-py
    return store.list_audit_events(req_id)


# OK: the client IP is recorded, not used to choose whose data is returned.
# Pins the scoping-method regex.
def record_client_ip(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    client_ip = headers.get("x-forwarded-for")
    # ok: mcp-authz-scope-from-request-header-py
    store.record_access(client_ip, session.user_id)
    return store.list_notes_by_org(session.org_id)


# OK: the header lands in a non-scope field, in a dict and as a keyword; the
# scope comes from the session. Pins the dict exclusion and both key regexes.
def list_events_from_ip(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    client_ip = headers.get("x-forwarded-for")
    # ok: mcp-authz-scope-from-request-header-py
    events = store.list_events({"org_id": session.org_id, "source_ip": client_ip})
    # ok: mcp-authz-scope-from-request-header-py
    events += store.list_notes(org_id=session.org_id, trace_ip=client_ip)
    # ok: mcp-authz-scope-from-request-header-py
    return events + store.list_notes(session.org_id, {"trace_ip": client_ip})


# OK: the header org reaches calls that do not choose whose data is returned:
# an audit write and quota lookups (S11 owns those). Pins the method and
# quota guards of every sink.
def audit_and_quota_by_header_org(token):
    session = resolve_session(store, token)
    headers = get_http_headers()
    header_org = headers.get("x-org-id")
    # ok: mcp-authz-scope-from-request-header-py
    store.record_access({"org_id": header_org, "user_id": session.user_id})
    # ok: mcp-authz-scope-from-request-header-py
    store.record_visit(org_id=header_org)
    # ok: mcp-authz-scope-from-request-header-py
    if store.get_quota_count(header_org) >= 10:
        raise PermissionError("quota exceeded")
    # ok: mcp-authz-scope-from-request-header-py
    if store.get_quota_count({"org_id": header_org}) >= 10:
        raise PermissionError("quota exceeded")
    # ok: mcp-authz-scope-from-request-header-py
    if store.get_quota_count(org_id=header_org) >= 10:
        raise PermissionError("quota exceeded")
    return store.list_notes_by_org(session.org_id)
