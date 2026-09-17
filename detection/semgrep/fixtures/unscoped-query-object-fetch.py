# Test fixture for rule: mcp-unscoped-query-object-fetch-py
#
# Python port of unscoped-query-object-fetch.js. The JS object-literal filter
# `{ id }` does not parse as Python; SQLAlchemy spells the same omission in
# kwargs. Two shapes measured: filter_by(id=...) leaves the tenant key out of
# the WHERE, and session.get(Model, pk) fetches straight by primary key.
#
# The dict.get negatives at the bottom pin the constraint that keeps the
# second shape usable in real code: config.get("timeout", 30) is not an
# authorization decision and must stay silent.


def get_note_vuln(db, note_id):
    # ruleid: mcp-unscoped-query-object-fetch-py
    return db.query(Note).filter_by(id=note_id).first()


def get_note_safe(db, note_id, workspace_id):
    # ok: mcp-unscoped-query-object-fetch-py
    return db.query(Note).filter_by(id=note_id, workspace_id=workspace_id).first()


def get_credential_vuln(session_, cred_id):
    """Primary-key fetch with no tenant column involved at all."""
    # ruleid: mcp-unscoped-query-object-fetch-py
    return session_.get(Credential, cred_id)


def get_credential_safe(session_, cred_id):
    """The fix is binding the tenant into the same lookup -- here via a
    scoped query instead of a bare primary-key get."""
    # ok: mcp-unscoped-query-object-fetch-py
    return (
        session_.query(Credential)
        .filter_by(id=cred_id, workspace_id=current_workspace().id)
        .first()
    )


def benign_dict_gets(config, cache, user_id):
    """dict.get spellings everywhere in real Python -- must NOT fire."""
    timeout = config.get("timeout", 30)
    name = cache.get(user_id, None)
    mode = settings.get("mode", "vuln")
    return timeout, name, mode


# Note: a $MODEL-shaped false positive existed here -- the rule's
# $S.get($MODEL, $ID) branch matched dict.get() calls whose second argument
# is a CapWord-looking STRING LITERAL (e.g. response.get('Item', {})), not a
# SQLAlchemy model class. Fixed via metavariable-pattern (mcp-object-authz.yml).
# A minimal fixture for this could NOT be added here: reproducing it requires
# the exact real-world file shape (awslabs/agent-squad's
# dynamodb_chat_storage.py) -- any isolated snippet, including one with a
# single added comment line, fails to reproduce the match at all (semgrep's
# Python-mode analysis is context/file-shape dependent for this pattern, not
# purely syntactic). Verified instead via a live scan against the real file:
# before-fix 2 findings, after-fix 0.
