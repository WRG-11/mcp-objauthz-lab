// Admin-guard exemption for the taint rule: a route behind an admin role guard is
// intentionally broad, so a client-id delete there is not the S7 bug for
// mcp-unscoped-query-object-fetch-taint. The pattern rule (no route context) still
// fires -- the deliberate disagreement, same shape as unscoped-query-taint.js.
const app = require("express")();

app.delete("/admin/thing/:id", [auth, flexUserRoleValid([ROLES.admin])], async (req, res) => {
  const { id } = req.params;
  // ok: mcp-unscoped-query-object-fetch-taint
  // ruleid: mcp-unscoped-query-object-fetch
  await repo.delete({ id });
});

app.delete("/note/:id", [auth], async (req, res) => {
  const { id } = req.params;
  // ruleid: mcp-unscoped-query-object-fetch-taint
  // ruleid: mcp-unscoped-query-object-fetch
  await repo.delete({ id });
});
