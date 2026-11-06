# Fixture for rule: mcp-ratelimit-scope-from-forwarded-header-py
#
# Python port of xff-for-ratelimit.js (real capture: a rate limiter that keyed
# its counter on X-Forwarded-For). A request header is client-controlled, so a
# caller who rotates it gets a fresh quota on every call. The FIRE half covers
# each shape the rule matches; the SILENT half keys the quota on the session.

from fastmcp.server.dependencies import get_http_headers


# ruleid: mcp-ratelimit-scope-from-forwarded-header-py
def create_note_with_quota_vuln(token: str, title: str, body: str):
    session = resolve_session(store, token)
    headers = get_http_headers()
    quota_key = headers.get("x-forwarded-for") or session.user_id
    if store.get_quota_count(quota_key) >= 10:
        raise ValueError("Quota exceeded")
    return store.create_note(org_id=session.org_id, owner_id=session.user_id, title=title, body=body)


# ruleid: mcp-ratelimit-scope-from-forwarded-header-py
async def api_call_with_rate_limit_vuln(token: str):
    session = resolve_session(store, token)
    headers = get_http_headers()
    rate_limit_key = headers["x-real-ip"] or session.user_id
    if store.is_rate_limited(rate_limit_key):
        raise ValueError("Rate limited")
    return store.make_api_call(session.user_id)


# ruleid: mcp-ratelimit-scope-from-forwarded-header-py
def create_resource_with_quota_vuln(token: str, name: str):
    session = resolve_session(store, token)
    headers = get_http_headers()
    store.increment_quota(headers.get("x-client-ip"))
    return store.create_resource(owner_id=session.user_id, name=name)


# ok: mcp-ratelimit-scope-from-forwarded-header-py
def create_note_with_quota_fixed(token: str, title: str, body: str):
    session = resolve_session(store, token)
    headers = get_http_headers()
    client_ip = headers.get("x-forwarded-for")
    logger.info("tool call", extra={"client_ip": client_ip})
    quota_key = session.user_id
    if store.get_quota_count(quota_key) >= 10:
        raise ValueError("Quota exceeded")
    return store.create_note(org_id=session.org_id, owner_id=session.user_id, title=title, body=body)
