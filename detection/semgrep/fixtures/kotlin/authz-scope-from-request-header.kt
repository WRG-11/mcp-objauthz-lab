// Test fixture for rule: mcp-authz-scope-from-request-header-kotlin
//
// S10 (forwarded-header-as-scope). Ktor/Spring MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// Corpus signatures (6 total, all POOL — STRONGEST CELL, MCP-NATIVE):
// - modelcontextprotocol/kotlin-sdk KtorServer.kt: val sessionId = call.request.header(MCP_SESSION_ID_HEADER) → transportManager.getTransport(sessionId) — CANONICAL S10
// - modelcontextprotocol/kotlin-sdk HostValidation.kt: val hostHeader = call.request.header(HttpHeaders.Host) → host-validation decision
// - modelcontextprotocol/kotlin-sdk StreamableHttpServerTransport.kt: val sessionId = call.request.header(MCP_SESSION_ID_HEADER) → session lookup
// - PortSwigger/mcp-server KtorServerManager.kt: val origin = call.request.header("Origin"); val host = call.request.header("Host") → DNS-rebinding / origin guard
// - six2dez/burp-ai-agent McpAccessControlPlugin.kt: RequestFacts(origin = call.request.headers["Origin"], host = call.request.headers["Host"]) → access control
// - six2dez/burp-ai-agent KtorMcpServerManager.kt: val authHeader = call.request.header(...) → auth
//
// Ecosystem corroboration (Ktor auth interceptors):
// - csieflyman/multi-projects: val apiKey = call.request.header(AuthConst.API_KEY_HEADER_NAME) in onAuthenticate
// - f-arslan/GptMap: val idToken = call.request.header("Authorization")?.removePrefix("Bearer ")
// - Elfocrash/L2jRest: val headerApiKey = context.call.request.header("x-api-key") → auth compare
//
// Two-way canary axis: header read for auth/session-scope/validation ⇒ FIRE; header read for tracing/negotiation ⇒ SILENT

import io.ktor.server.request.*
import io.ktor.http.*

// FIRE: call.request.header(MCP_SESSION_ID_HEADER) → getTransport(...) — CANONICAL S10
suspend fun noteGetScopedCanonicalVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val sessionId = call.request.header("Mcp-Session-Id")
    return transportManager.getTransport(sessionId)
}

// FIRE: call.request.header("Authorization"|"x-api-key"|"Origin"|"Host") → auth/validation decision
suspend fun noteGetScopedAuthVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val authHeader = call.request.header("Authorization")?.removePrefix("Bearer ")
    return repo.authenticate(authHeader)
}

// FIRE: header value used to select org scope in a repository call (authz decision)
suspend fun noteGetScopedVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val headerOrg = call.request.headers["x-org-id"] ?: session.orgId
    return repo.listNotesByOrg(headerOrg)
}

// FIRE: call.request.header() form with authz decision
suspend fun noteGetScopedHeaderVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    val headerOrg = call.request.header("x-org-id") ?: session.orgId
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

// SILENT: header read for tracing/negotiation (X-Real-IP, User-Agent, Content-Type, X-GitHub-Event)
suspend fun logTracing(call: ApplicationCall) {
    // ok: mcp-authz-scope-from-request-header-kotlin
    val realIp = call.request.header("X-Real-IP")
    val ua = call.request.headers["User-Agent"]
    val event = call.request.header("X-GitHub-Event")
    logger.info { "tracing realIp=$realIp ua=$ua event=$event" }
}

fun resolveSession(token: String): Session = TODO()
class Session(val orgId: String, val clientIp: String)
class Repo { 
    fun listNotesByOrg(orgId: String) = TODO()
    fun listNotesForClientIp(ip: String) = TODO()
    fun findNoteBy(id: String, orgId: String) = TODO()
    fun authenticate(token: String?) = TODO()
}
val repo = Repo()
val transportManager = object { fun getTransport(id: String?) = TODO() }
val logger = TODO()