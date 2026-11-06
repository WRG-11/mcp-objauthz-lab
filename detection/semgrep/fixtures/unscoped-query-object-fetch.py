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


# SQLAlchemy 2.0 spells the lookup select(Model).where(Model.id == x). The
# branch for it only reports inside a route handler whose parameter is the id:
# a service method's id comes from a caller that may already have checked it,
# and measured on one real FastAPI server the unrestricted shape fired 72
# times for 3 real bugs.


@router.post("/{server_id}/start")
async def start_server_vuln(server_id: UUID, db: AsyncSession = Depends(get_db)):
    # ruleid: mcp-unscoped-query-object-fetch-py
    result = await db.execute(select(Server).where(Server.id == server_id))
    return result.scalar_one_or_none()


@router.get("/{server_id}")
def get_server_reversed_vuln(server_id: UUID, db: Session = Depends(get_db)):
    # ruleid: mcp-unscoped-query-object-fetch-py
    return db.execute(select(Server).where(server_id == Server.id)).scalar_one()


@router.delete("/{server_id}")
async def delete_server_status_filter_vuln(server_id: UUID, db: AsyncSession = Depends(get_db)):
    """A second filter that is not a tenant key does not scope the read."""
    # ruleid: mcp-unscoped-query-object-fetch-py
    query = select(Server).where(Server.id == server_id).where(Server.status == "stopped")
    return (await db.execute(query)).scalar_one_or_none()


@router.get("/{server_id}/logs")
async def server_logs_logged_vuln(server_id: UUID, db: AsyncSession = Depends(get_db)):
    """Passing the id to a call that is not a check does not authorize it."""
    await log_access(db, server_id)
    # ruleid: mcp-unscoped-query-object-fetch-py
    return (await db.execute(select(Server).where(Server.id == server_id))).scalar_one()


@router.get("/keys/{key_id}")
async def get_key_owned(key_id: UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    """The owner filter is chained onto the same query."""
    # ok: mcp-unscoped-query-object-fetch-py
    query = select(ApiKey).where(ApiKey.id == key_id).where(ApiKey.user_id == user.id)
    return (await db.execute(query)).scalar_one_or_none()


@router.get("/keys/{key_id}/reversed")
async def get_key_owned_reversed(key_id: UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    # ok: mcp-unscoped-query-object-fetch-py
    query = select(ApiKey).where(ApiKey.id == key_id).where(user.id == ApiKey.user_id)
    return (await db.execute(query)).scalar_one_or_none()


@router.get("/orgs/{organization_id}")
async def get_org_member_checked(organization_id: UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    """The id is passed to a membership check before the query."""
    membership = await get_user_membership(db, user.id, organization_id)
    if not membership:
        raise HTTPException(status_code=403)
    # ok: mcp-unscoped-query-object-fetch-py
    return (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one()


@router.put("/orgs/{organization_id}")
async def update_org_admin_checked(organization_id: UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    await require_org_admin(db, user.id, organization_id)
    # ok: mcp-unscoped-query-object-fetch-py
    return (await db.execute(select(Organization).where(Organization.id == organization_id))).scalar_one()


@router.patch("/orgs/{organization_id}/name")
def rename_org_checked(organization_id: UUID, user=Depends(current_user), db: Session = Depends(get_db)):
    verify_org_owner(db, user.id, organization_id)
    # ok: mcp-unscoped-query-object-fetch-py
    return db.execute(select(Organization).where(Organization.id == organization_id)).scalar_one()


@router.get("/orgs/{organization_id}/plan")
def org_plan_checked(organization_id: UUID, user=Depends(current_user), db: Session = Depends(get_db)):
    allowed = can_view_org(db, user.id, organization_id)
    if not allowed:
        raise HTTPException(status_code=403)
    # ok: mcp-unscoped-query-object-fetch-py
    return db.execute(select(Organization).where(Organization.id == organization_id)).scalar_one()


async def load_server(db: AsyncSession, server_id: UUID):
    """A service function, not a route handler: its caller decides."""
    # ok: mcp-unscoped-query-object-fetch-py
    return (await db.execute(select(Server).where(Server.id == server_id))).scalar_one()


@cache.memoize(timeout=60)
async def cached_server(server_id: UUID, db: AsyncSession):
    """Decorated, but not with a route method."""
    # ok: mcp-unscoped-query-object-fetch-py
    return (await db.execute(select(Server).where(Server.id == server_id))).scalar_one()


@router.get("/servers/current")
async def current_server(db: AsyncSession = Depends(get_db), user=Depends(current_user)):
    """The id is not a parameter of the handler."""
    # ok: mcp-unscoped-query-object-fetch-py
    return (await db.execute(select(Server).where(Server.id == user.server_id))).scalar_one()
