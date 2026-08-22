// Test fixture for rule: mcp-unscoped-query-object-fetch
//
// The query-scoped shape: a repository fetch where the tenant key is either
// present in the filter (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.

async function getCredentialVuln({ id }) {
  // ruleid: mcp-unscoped-query-object-fetch
  return repo.findOneBy({ id });
}

async function getCredentialSafe({ id, workspaceId }) {
  // ok: mcp-unscoped-query-object-fetch
  return repo.findOneBy({ id, workspaceId });
}

async function getNoteVulnWhere({ id }) {
  // ruleid: mcp-unscoped-query-object-fetch
  return repo.findOne({ where: { id } });
}

async function getNoteSafeWhere({ id, orgId }) {
  // ok: mcp-unscoped-query-object-fetch
  return repo.findOne({ where: { id, orgId } });
}

async function deleteRecordVuln({ id }) {
  // ruleid: mcp-unscoped-query-object-fetch
  return repo.delete({ id });
}

async function deleteRecordSafe({ id, projectId }) {
  // ok: mcp-unscoped-query-object-fetch
  return repo.delete({ id, projectId });
}
