// Test fixture for rule: mcp-unscoped-query-object-fetch-kotlin
//
// The query-scoped shape: a repository fetch where the tenant key is either
// present in the filter (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.
//
// Corpus signatures (4 total, all ECO - no ORM by-id in pool's kotlin MCP repos):
// - Spring-Data-Kotlin: cheese10yun/blog-sample stockRepository.findByIdOrNull(stockId)
// - Exposed DSL: eclipse-apoapsis/ort-server EnvironmentsTable.selectAll().where { EnvironmentsTable.id eq environmentId }
// - Exposed DSL: way-zer/ScriptAgent4MindustryExt Table.selectAll().where { Table.id eq id }.firstOrNull()
// - Exposed DSL: beatmaps-io/beatsaver-main Beatmap.selectAll().where { Beatmap.id eq it.key.toInt(16) }
//
// SILENT (predicate ANDs an owner/tenant column - ECO):
// - beatmaps-io/beatsaver-main quest.kt: User.selectAll().where { (User.id eq sess.userId) }
// - beatmaps-io/beatsaver-main review.kt: Review.selectAll().where { Review.mapId eq updateMapId and (Review.userId eq reqUid) and ... }
//
// NOTE: No ORM by-id found in pool's kotlin MCP repos (their findById = in-memory registries in intellij-community).
// Idiom captured from ecosystem Spring-Data-Kotlin + Exposed. Shape is standard and N-ready.
//
// Two-way canary axis: id-only predicate ⇒ FIRE; predicate AND owner/tenant column ⇒ SILENT

// FIRE: Spring Data Kotlin findByIdOrNull with id only
suspend fun getCredentialVuln(id: String): Any? {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return repo.findByIdOrNull(id)
}

// FIRE: Spring Data Kotlin findById with id only
suspend fun getCredentialVuln2(id: String): Any? {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return repo.findById(id)
}

// FIRE: Exposed DAO EntityClass findById with id only
suspend fun getExposedVuln(id: String): Any? {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return dao.findById(id)
}

// FIRE: Exposed DSL selectAll().where { Table.id eq id } — id-only predicate
suspend fun getExposedDslVuln(id: String): Any? {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return TABLE.selectAll().where { TABLE.id eq id }.firstOrNull()
}

// FIRE: deleteById with id only
suspend fun deleteRecordVuln(id: String): Any? {
    // ruleid: mcp-unscoped-query-object-fetch-kotlin
    return repo.deleteById(id)
}

// OK: Spring Data with tenant key (if method exists)
suspend fun getCredentialSafe(id: String, workspaceId: String): Any? {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return repo.findById(id = id, workspaceId = workspaceId)
}

// OK: Exposed DSL with owner column in predicate (SILENT - owner/tenant scoped)
suspend fun getExposedDslSafe(id: String, userId: String): Any? {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return TABLE.selectAll().where { TABLE.id eq id and (TABLE.userId eq userId) }.firstOrNull()
}

// OK: Exposed DSL with multiple owner columns (SILENT)
suspend fun getReviewSafe(mapId: String, userId: String): Any? {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return ReviewTable.selectAll().where { 
        ReviewTable.mapId eq mapId and (ReviewTable.userId eq userId) 
    }.firstOrNull()
}

// SILENT: derived finder with tenant column — findByIdAndTenantId(id, tenant)
suspend fun getDerivedSafe(id: String, tenantId: String): Any? {
    // ok: mcp-unscoped-query-object-fetch-kotlin
    return repo.findByIdAndTenantId(id, tenantId)
}

class Repo {
    suspend fun findByIdOrNull(id: String): Any? = TODO()
    suspend fun findById(id: String): Any? = TODO()
    suspend fun findById(id: String, workspaceId: String): Any? = TODO()
    suspend fun findByIdAndTenantId(id: String, tenantId: String): Any? = TODO()
    suspend fun deleteById(id: String): Any? = TODO()
}
class ExposedDao {
    suspend fun findById(id: String): Any? = TODO()
}
val repo = Repo()
val dao = ExposedDao()

object TABLE : Table() {
    val id = integer("id")
    val userId = integer("user_id")
}
object ReviewTable : Table() {
    val mapId = integer("map_id")
    val userId = integer("user_id")
}