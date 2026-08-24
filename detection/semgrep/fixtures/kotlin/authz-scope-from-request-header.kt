// Test fixture for rule: mcp-authz-scope-from-request-header-kotlin
//
// S10 (forwarded-header-as-scope). Ktor/Spring MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// TWO-WAY CANARY:
// - FIRE: header value feeds an authz decision (scope/org-id selection, listNotesByOrg(headerValue))
// - SILENT: header read ONLY for logging (no authz decision)

import io.ktor.server.request.*

// FIRE: header value used to select org scope in a repository call (authz decision)
suspend fun noteGetScopedVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val headerOrg = call.request.headers["x-org-id"] ?: session.orgId
    return repo.listNotesByOrg(headerOrg)
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
suspend fun noteGetScopedByIpVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val fwd = call.request.headers["x-forwarded-for"] ?: session.clientIp
    return repo.listNotesForClientIp(fwd)
}

// FIRE: header used directly as orgId in a query filter (authz decision)
suspend fun noteGetByQueryVuln(call: ApplicationCall, token: String, id: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val headerOrg = call.request.headers["x-org-id"] ?: session.orgId
    return repo.findNoteBy(id = id, orgId = headerOrg)
}

// OK: scope comes from the session; no header is consulted at all.
suspend fun noteGetScopedFixed(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ok: mcp-authz-scope-from-request-header-kotlin
    return repo.listNotesByOrg(session.orgId)
}

// OK (legitimate neighbor): a non-scope header read for logging only.
suspend fun logRequest(call: ApplicationCall) {
    // ok: mcp-authz-scope-from-request-header-kotlin
    val reqId = call.request.headers["x-request-id"]
    logger.info { "tool invoked, reqId=$reqId" }
}

// SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
// This is the two-way canary: reading XFF for logging must NOT fire.
suspend fun logClientIp(call: ApplicationCall) {
    // ok: mcp-authz-scope-from-request-header-kotlin
    val clientIp = call.request.headers["x-forwarded-for"]
    logger.info { "rate-limit check, clientIp=$clientIp" }
}

// SILENT: scope-shaped header read into a variable but NEVER used for authz
suspend fun readHeaderButDontUse(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ok: mcp-authz-scope-from-request-header-kotlin
    val _unused = call.request.headers["x-org-id"]
    return repo.listNotesByOrg(session.orgId)
}

fun resolveSession(token: String): Session = TODO()
class Session(val orgId: String, val clientIp: String)
class Repo { fun listNotesByOrg(orgId: String) = TODO(); fun listNotesForClientIp(ip: String) = TODO(); fun findNoteBy(id: String, orgId: String) = TODO() }
val repo = Repo()
val logger = TODO()