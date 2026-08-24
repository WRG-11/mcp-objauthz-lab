// Test fixture for rule: mcp-unscoped-query-object-fetch-kotlin
//
// The query-scoped shape: a repository fetch where the tenant key is either
// present in the filter (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.

suspend fun getCredentialVuln(id: String) {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return repo.findById(id)
}

suspend fun getCredentialSafe(id: String, workspaceId: String) {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return repo.findById(id = id, workspaceId = workspaceId)
}

suspend fun getNoteVuln(id: String) {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return repo.findOneBy(mapOf("id" to id))
}

suspend fun getNoteSafe(id: String, orgId: String) {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return repo.findOneBy(mapOf("id" to id, "orgId" to orgId))
}

suspend fun deleteRecordVuln(id: String) {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return repo.deleteById(id)
}

suspend fun deleteRecordSafe(id: String, projectId: String) {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return repo.deleteById(id = id, projectId = projectId)
}

class Repo {
    suspend fun findById(id: String): Any = TODO()
    suspend fun findById(id: String, workspaceId: String): Any = TODO()
    suspend fun findOneBy(filter: Map<String, Any>): Any = TODO()
    suspend fun deleteById(id: String): Any = TODO()
    suspend fun deleteById(id: String, projectId: String): Any = TODO()
}
val repo = Repo()