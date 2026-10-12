# Test fixture for rule: mcp-token-scope-claim-overrides-session-py-ternary (S13 - Python)
#
# S13 (JWT/token scope confusion). Python spelling: ternary with scope/aud parameter.

def get_notes_by_token_scope_vuln(token, scope):
    session = resolve_session(token)
    # ruleid: mcp-token-scope-claim-overrides-session-py-ternary
    effective_org_id = scope if scope else session.org_id
    return store.list_notes_by_org(effective_org_id)

def get_notes_by_token_scope_vuln2(token, aud):
    session = resolve_session(token)
    # ruleid: mcp-token-scope-claim-overrides-session-py-ternary
    effective_org_id = aud if aud is not None else session.org_id
    return store.list_notes_by_org(effective_org_id)

def get_notes_by_token_scope_safe(token, scope):
    session = resolve_session(token)
    # ok: mcp-token-scope-claim-overrides-session-py-ternary
    return store.list_notes_by_org(session.org_id)

def get_notes_by_token_scope_safe2(token, aud):
    session = resolve_session(token)
    # ok: mcp-token-scope-claim-overrides-session-py-ternary
    return store.list_notes_by_org(session.org_id)