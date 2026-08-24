// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass-kotlin
//
// S4 (wildcard/sentinel bypass). A magic "all" or "*" sentinel on a scope
// parameter is honored in an AUTHORIZATION CONTEXT (it controls whether to
// widen scope and return all tenants' data) without a role check.
// A textual "*" or "all" comparison in markup rendering, UI filters, or
// logging is NOT an authz decision and must stay silent.
//
// TWO-WAY CANARY:
// - FIRE: wildcard in authz bypass context (gates scope widening, returns all orgs' data)
// - SILENT: wildcard in non-authz context (markup, UI filter, logging)

// FIRE: wildcard comparison gates returning all orgs' data (authz bypass)
suspend fun vulnExport(token: String, org_id: String) {
    val session = resolveSession(token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-kotlin
    if (org_id == "*" || org_id == "all") {
        return repo.listAllNotes()
    }
    return repo.listNotesByOrg(session.orgId)
}

// FIRE: when expression with wildcard selecting all-orgs vs scoped data (authz bypass)
suspend fun vulnExportWhen(token: String, org_id: String) {
    val session = resolveSession(token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-kotlin
    return when (org_id) {
        "*", "all" -> repo.listAllNotes()
        else -> repo.listNotesByOrg(session.orgId)
    }
}

// FIRE: wildcard check skips normal org scoping (authz bypass)
suspend fun vulnExportSkipScope(token: String, org_id: String) {
    val session = resolveSession(token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-kotlin
    if (org_id == "*") {
        return repo.listAllNotes()
    }
    // no org scoping in this branch -- wildcard bypassed it
    return repo.listAllNotes()
}

// OK: wildcard guarded by admin role check
suspend fun fixedExportGuarded(token: String, org_id: String) {
    val session = resolveSession(token)
    requireAdminRole(session)
    // ok: mcp-wildcard-sentinel-scope-bypass-kotlin
    if (org_id == "*" || org_id == "all") {
        return repo.listAllNotes()
    }
    return repo.listNotesByOrg(session.orgId)
}

// SILENT: wildcard in markup rendering (textual, not authz)
// The parameter name matches scope regex but context is markup, not authz
fun renderMarkdown(text: String): String {
    // ok: mcp-wildcard-sentinel-scope-bypass-kotlin
    return text.replace(Regex("\\*(.+?)\\*"), "<b>\$1</b>")
}

// SILENT: wildcard in UI search filter (textual comparison, not authz)
// The variable name matches scope regex but it's a UI filter value, not scope
fun filterNotesByScope(notes: List<Note>, scope: String): List<Note> {
    // ok: mcp-wildcard-sentinel-scope-bypass-kotlin
    if (scope == "all") {
        return notes // UI "show all" filter, not authz bypass
    }
    return notes.filter { it.scope == scope }
}

// SILENT: wildcard in logging (textual, not authz)
fun logScopeValue(scope: String) {
    // ok: mcp-wildcard-sentinel-scope-bypass-kotlin
    if (scope == "*") {
        logger.info("wildcard scope requested")
    }
}

fun resolveSession(token: String): Session = TODO()
fun requireAdminRole(session: Session) = TODO()
class Session(val orgId: String)
class Note(val scope: String)
class Repo { fun listAllNotes() = TODO(); fun listNotesByOrg(orgId: String) = TODO() }
val repo = Repo()
val logger = TODO()