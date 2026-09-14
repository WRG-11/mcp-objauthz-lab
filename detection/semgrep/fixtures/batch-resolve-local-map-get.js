// Real-capture false-positive fixture for: mcp-batch-resolve-missing-per-item-scope-filter
//
// Captured from a danny-avila/LibreChat scan (2026-09-14). `.map(id => coll.get(id))`
// where `coll` is an in-memory Map already populated from a scoped query upstream
// is one of the most common JS idioms; it is NOT a batch store fetch. The bare
// `.get`/`.find` accessor is what separates a Map/cache lookup from a domain store
// method (`store.getNote`, `repo.findById`). Both cases must stay SILENT.
//
// Hardening: $METHOD must be a suffixed accessor (`^(get|find)[A-Za-z0-9_]+$`),
// so a bare `.get` / `.find` no longer matches. Flagging these was the false
// positive that would get the rule switched off.

function batchOverAuthorizedMap(fileIds, authorizedFilesById) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  return fileIds.map((fileId) => authorizedFilesById.get(fileId)).filter(Boolean);
}

function batchOverPreparationsMap(resolvedAgents, runtimeAgentPreparations) {
  // ok: mcp-batch-resolve-missing-per-item-scope-filter
  return resolvedAgents.map((agent) => runtimeAgentPreparations.get(agent));
}
