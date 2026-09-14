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

// Prisma-style mutation: the scope key lives inside a nested `where` object, the
// same shape an ORM delete/update takes. The suppressor knew findOne({where})
// but not delete/update({where}), so the scoped form was a false positive.
async function deletePrismaWhereVuln({ id }) {
  // ruleid: mcp-unscoped-query-object-fetch
  return prisma.record.delete({ where: { id } });
}

async function deletePrismaWhereSafe({ id, workspaceId }) {
  // ok: mcp-unscoped-query-object-fetch
  return prisma.record.delete({ where: { id, workspaceId } });
}
