// Taint-mode fixture: mcp-unscoped-query-object-fetch-taint tracks whether the id
// reaching a fetch/delete came from the CLIENT (req.*) or a SERVER-TRUSTED source
// (a res.locals object loaded by middleware, or the session). The pattern-based
// sibling mcp-unscoped-query-object-fetch cannot see provenance, so the two rules
// deliberately DISAGREE on deleteMiddlewareLoaded below -- that disagreement is the
// point: taint is the higher-precision signal, the pattern rule the wider net.

async function deleteVuln(req, res) {
  const { id } = req.params;
  // ruleid: mcp-unscoped-query-object-fetch-taint
  // ruleid: mcp-unscoped-query-object-fetch
  return repo.delete({ id });
}

async function deleteMiddlewareLoaded(req, res) {
  const thread = res.locals.thread;
  // ok: mcp-unscoped-query-object-fetch-taint
  // ruleid: mcp-unscoped-query-object-fetch
  return repo.delete({ id: thread.id });
}

async function deleteScoped(req, res) {
  const { id } = req.params;
  const workspaceId = req.session.workspaceId;
  // ok: mcp-unscoped-query-object-fetch-taint
  // ok: mcp-unscoped-query-object-fetch
  return repo.delete({ where: { id, workspaceId } });
}

async function fetchVuln(req, res) {
  const id = req.query.id;
  // ruleid: mcp-unscoped-query-object-fetch-taint
  // ruleid: mcp-unscoped-query-object-fetch
  return repo.findOneBy({ id });
}
