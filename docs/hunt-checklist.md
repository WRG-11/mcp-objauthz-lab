# Hunt checklist — object-level authorization in MCP

Use this when auditing a real multi-tenant MCP server (one you own or are
authorized to test). The bug class is "the server authenticates *who you are*
but forgets to check *whether you may touch this object*":

- [ ] **Client-supplied scope trusted as authorization (→ S2).** A tool takes an
  `org_id` / `project_id` / `tenant_id` argument and uses it to *scope the query*
  instead of *checking it against the caller's membership*.
- [ ] **Membership check decoupled from object resolution.** The tool verifies
  the caller belongs to some org/project, but loads the object by a *different* id
  without confirming the object lives under that membership.
- [ ] **Inconsistent authorization — the single outlier (→ S1).** Most object
  tools check; one or two do not. Read **every** tool that resolves an object by id.
  The forgotten one is usually a less-glamorous verb (`delete`, `archive`, `export`).
- [ ] **Reads guarded, mutations not.** `get`/`list` are scoped but `update`/`delete`
  slipped through — or vice-versa.
- [ ] **Wildcard / sentinel short-circuit (→ S4).** A special value (`'all'`,
  `'*'`, empty, `0`, `null`) skips the scope filter entirely.
- [ ] **Role / token-type bypass (→ S5).** An "admin" or "service" code path
  skips the per-object check.
- [ ] **List → get asymmetry (→ S3).** `list` only returns your org's objects, so
  ids feel "private" — but `get`/`batch-get` accept *any* id and the ids are
  guessable or enumerable.
- [ ] **Create/update accepting a foreign parent (→ S6).** `create(parent_id=…)`
  accepts a parent the caller is not a member of, injecting an object into
  another tenant.
- [ ] **Resource URI segment trusted as scope (→ S8).** A `resources/read`
  handler binds a tenant/scope key straight from a URI template variable
  instead of the session — easy to miss because a review that only reads
  `tools/*` handlers never looks at `resources/*` at all.
- [ ] **A value round-tripped through the client trusted as authorization
  (→ S9).** A tool decodes a token/grant/cursor produced by an earlier tool
  call and serves the object it names, with no re-check against the current
  session — "an earlier tool already authorized this" is a client-side
  claim, not a server fact, and it is not fixed by making the value
  cryptographically signed if the redeeming tool never re-checks it.

The exploit primitive is always the same: authenticate as tenant **B**, call the
suspect tool with an object or scope that belongs to tenant **A**, and see whether
you get **A**'s data (or mutate it). Confirm a fix the same way the PoC here does
— **two-way**: the cross-tenant call must be blocked *and* the legitimate
same-tenant call must still succeed.
