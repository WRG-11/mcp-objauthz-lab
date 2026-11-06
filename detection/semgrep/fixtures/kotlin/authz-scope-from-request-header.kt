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

// The rule is a taint rule, so a finding sits on the SINK: the scoping call.
// `ruleid:` markers are above that call.

// OK: Mcp-Session-Id routes the request to its transport. It is the MCP
// session handle, unguessable and issued by the server, not a client-chosen
// tenant scope, and it is outside the rule's header list. (Marked `ruleid`
// before, which contradicted the rule.)
suspend fun transportBySessionId(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ok: mcp-authz-scope-from-request-header-kotlin
    val sessionId = call.request.header("Mcp-Session-Id")
    return transportManager.getTransport(sessionId)
}

// OK: a bearer token checked by the server is authentication, not a
// client-chosen scope. (Marked `ruleid` before.)
suspend fun authenticateWithBearer(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    // ok: mcp-authz-scope-from-request-header-kotlin
    val authHeader = call.request.header("Authorization")?.removePrefix("Bearer ")
    return repo.authenticate(authHeader)
}

// FIRE: header value used to select org scope in a repository call (authz decision)
suspend fun noteGetScopedVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    val headerOrg = call.request.headers["x-org-id"] ?: session.orgId
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    return repo.listNotesByOrg(headerOrg)
}

// FIRE: call.request.header() form with authz decision
suspend fun noteGetScopedHeaderVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    val headerOrg = call.request.header("x-org-id") ?: session.orgId
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    return repo.listNotesByOrg(headerOrg)
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
suspend fun noteGetScopedByIpVuln(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    val fwd = call.request.headers["x-forwarded-for"] ?: session.clientIp
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    return repo.listNotesForClientIp(fwd)
}

// FIRE: header used directly as orgId in a query filter (authz decision)
suspend fun noteGetByQueryVuln(call: ApplicationCall, token: String, id: String) {
    val session = resolveSession(token)
    val headerOrg = call.request.headers["x-org-id"] ?: session.orgId
    // ruleid: mcp-authz-scope-from-request-header-kotlin
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

// FIRE: Spring @RequestHeader parameter feeding a scoping call.
fun projectListVuln(@RequestHeader("X-Tenant-Id") tenant: String): List<Project> {
    // ruleid: mcp-authz-scope-from-request-header-kotlin
    return repo.findProjects(tenant)
}

// OK (legitimate neighbor): a correlation header passed to a list call is not
// a scope. Pins the header-name regex of the Ktor source.
suspend fun listByRequestId(call: ApplicationCall) {
    val reqId = call.request.headers["x-request-id"]
    // ok: mcp-authz-scope-from-request-header-kotlin
    return repo.listAuditEvents(reqId)
}

// OK: the same through @RequestHeader. Pins its header-name regex.
fun listByRequestIdSpring(@RequestHeader("X-Request-Id") reqId: String) {
    // ok: mcp-authz-scope-from-request-header-kotlin
    return repo.listAuditEvents(reqId)
}

// OK: the client IP is recorded, not used to choose whose data is returned.
// Pins the scoping-method regex.
suspend fun recordClientIp(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    val clientIp = call.request.header("x-forwarded-for")
    // ok: mcp-authz-scope-from-request-header-kotlin
    repo.recordAccess(clientIp)
    return repo.listNotesByOrg(session.orgId)
}

// OK: a quota lookup keyed on the forwarded header is S11, not S10.
suspend fun quotaByForwardedIp(call: ApplicationCall, token: String) {
    val session = resolveSession(token)
    val fwd = call.request.header("x-forwarded-for")
    // ok: mcp-authz-scope-from-request-header-kotlin
    if (repo.getQuotaCount(fwd) >= 10) throw IllegalStateException("quota")
    return repo.listNotesByOrg(session.orgId)
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