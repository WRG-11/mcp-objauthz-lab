# Test fixture for rule: mcp-write-parent-from-client-argument-py
#
# Python port of write-parent-from-client-argument.js. As predicted in the
# wave brief, the JS rule does not port directly -- its core pattern is an
# object literal (`{ orgId: x }`), which cannot parse as Python. This sibling
# carries the same logic in kwargs spelling.
#
# The `ok:` cases matter as much as the `ruleid:` ones. A rule that fires on
# every create taking an org argument would flag legitimate cross-team tools,
# get switched off, and protect nothing.


# The plainest form: the argument is the write target.
def create_in_org_vuln(store, token, org_id, title, body):
    session = resolve_session(store, token)
    # ruleid: mcp-write-parent-from-client-argument-py
    return store.create_note(org_id=org_id, owner_id=session.user_id,
                             title=title, body=body)


# Correct: the destination is the session's own scope; the argument, if any,
# is ignored. Passed straight from the session so the value's origin is on
# the call line itself.
def create_in_org_safe(store, token, org_id, title):
    session = resolve_session(store, token)
    # ok: mcp-write-parent-from-client-argument-py
    return store.create_note(org_id=session.org_id, owner_id=session.user_id,
                             title=title)


# Correct: a cross-team tool that genuinely accepts a destination, and proves
# membership of it first. Flagging this one would be the false positive that
# gets the rule disabled.
def create_in_org_checked(store, token, org_id, title):
    session = resolve_session(store, token)
    require_org_access(session, org_id)
    # ok: mcp-write-parent-from-client-argument-py
    return store.create_note(org_id=org_id, owner_id=session.user_id,
                             title=title)


# Correct: a write with no tenant-shaped key at all is not this rule's
# business.
def create_comment_safe(store, token, note_id, body):
    session = resolve_session(store, token)
    # ok: mcp-write-parent-from-client-argument-py
    return store.create_comment(note_id=note_id, author_id=session.user_id,
                                body=body)
