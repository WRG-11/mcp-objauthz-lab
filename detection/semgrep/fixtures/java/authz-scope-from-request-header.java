// Test fixture for rule: mcp-authz-scope-from-request-header-java
//
// S10 (forwarded-header-as-scope). Spring/WebFlux MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// Corpus signatures (5 total, all POOL + ECO):
// - eugenp/tutorials: @RequestHeader("Authorization") String authHeader
// - eugenp/tutorials: @RequestHeader("X-Conversation-ID") String conversationId → memory scope
// - eugenp/tutorials: @RequestHeader(CLIENT_ID_HEADER) String clientId → Concurrency.protect scope
// - apache/dubbo: @Activate(onClass="RequestHeader") framework confirmation
// - jakarta.servlet.http.HttpServletRequest.getHeader(...) via eugenp requestheader/*
//
// Two-way canary axis: is the header read (inbound, for a decision) or written (outbound) /
// read for a non-authz concern (locale, tracing, negotiation)? (write or non-authz ⇒ SILENT)

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

// The rule is a taint rule, so a finding sits on the SINK: the call argument
// that selects the scope. `ruleid:` markers are above the scoping call.

// FIRE: @RequestHeader("X-Org-Id") String org → tenantScope(org) / used in access decision
public Mono<Note> noteGetScopedVuln(ServerWebExchange exchange, String token) {
    Session session = resolveSession(token);
    String headerOrg = exchange.getRequest().getHeaders().getFirst("x-org-id") != null
        ? exchange.getRequest().getHeaders().getFirst("x-org-id")
        : session.getOrgId();
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.listNotesByOrg(headerOrg);
}

// FIRE: @RequestHeader annotation form with authz decision
public Mono<Note> noteGetScopedAnnotationVuln(
        @RequestHeader("X-Org-Id") String orgId,
        String token) {
    Session session = resolveSession(token);
    String effectiveOrgId = orgId != null ? orgId : session.getOrgId();
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.listNotesByOrg(effectiveOrgId);
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
public Mono<Note> noteGetScopedByIpVuln(ServerWebExchange exchange, String token) {
    Session session = resolveSession(token);
    String fwd = exchange.getRequest().getHeaders().getFirst("x-forwarded-for") != null
        ? exchange.getRequest().getHeaders().getFirst("x-forwarded-for")
        : session.getClientIp();
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.listNotesForClientIp(fwd);
}

// FIRE: header used directly as orgId in a query filter (authz decision)
public Mono<Note> noteGetByQueryVuln(ServerWebExchange exchange, String token, String id) {
    Session session = resolveSession(token);
    String headerOrg = exchange.getRequest().getHeaders().getFirst("x-org-id") != null
        ? exchange.getRequest().getHeaders().getFirst("x-org-id")
        : session.getOrgId();
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.findNoteBy(id, headerOrg);
}

// OK: scope comes from the session; no header is consulted at all.
public Mono<Note> noteGetScopedFixed(ServerWebExchange exchange, String token) {
    Session session = resolveSession(token);
    // ok: mcp-authz-scope-from-request-header-java
    return repo.listNotesByOrg(session.getOrgId());
}

// OK (legitimate neighbor): a non-scope header read for logging only.
public void logRequest(ServerWebExchange exchange) {
    // ok: mcp-authz-scope-from-request-header-java
    String reqId = exchange.getRequest().getHeaders().getFirst("x-request-id");
    logger.info("tool invoked, reqId={}", reqId);
}

// SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
// This is the two-way canary: reading XFF for logging must NOT fire.
public void logClientIp(ServerWebExchange exchange) {
    // ok: mcp-authz-scope-from-request-header-java
    String clientIp = exchange.getRequest().getHeaders().getFirst("x-forwarded-for");
    logger.info("rate-limit check, clientIp={}", clientIp);
}

// SILENT: scope-shaped header read into a variable but NEVER used for authz
public Mono<Note> readHeaderButDontUse(ServerWebExchange exchange, String token) {
    Session session = resolveSession(token);
    // ok: mcp-authz-scope-from-request-header-java
    String _unused = exchange.getRequest().getHeaders().getFirst("x-org-id");
    return repo.listNotesByOrg(session.getOrgId());
}

// SILENT: header read for locale/negotiation (Accept-Language, User-Agent)
public void logLocale(ServerWebExchange exchange) {
    // ok: mcp-authz-scope-from-request-header-java
    String locale = exchange.getRequest().getHeaders().getFirst("accept-language");
    logger.info("locale={}", locale);
}

// FIRE: servlet getHeader feeding a scoping call.
public Note projectFindVuln(HttpServletRequest request) {
    String tenant = request.getHeader("X-Tenant-Id");
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.findProjects(tenant);
}

// FIRE: @RequestHeader(name = ...) form.
public Note workspaceSearchVuln(@RequestHeader(name = "X-Workspace-Id") String ws, String query) {
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.searchDocuments(query, ws);
}

// FIRE: @RequestHeader(value = ...) form.
public Note accountListVuln(@RequestHeader(value = "X-Account-Id") String account) {
    // ruleid: mcp-authz-scope-from-request-header-java
    return repo.listInvoices(account);
}

// OK (legitimate neighbor): a correlation header passed to a list call is not
// a scope. Pins the header-name regex.
public Note listByRequestId(@RequestHeader("X-Request-Id") String reqId) {
    // ok: mcp-authz-scope-from-request-header-java
    return repo.listAuditEvents(reqId);
}

// OK: the same neighbor through the servlet accessor. Pins the header-name
// regex of the accessor source.
public Note listByServletRequestId(HttpServletRequest request) {
    String reqId = request.getHeader("X-Request-Id");
    // ok: mcp-authz-scope-from-request-header-java
    return repo.listAuditEvents(reqId);
}

// OK: the client IP is recorded, not used to choose whose data is returned.
// Pins the scoping-method regex.
public Note recordClientIp(HttpServletRequest request, String token) {
    Session session = resolveSession(token);
    String clientIp = request.getHeader("X-Forwarded-For");
    // ok: mcp-authz-scope-from-request-header-java
    repo.recordAccess(clientIp);
    return repo.listNotesByOrg(session.getOrgId());
}

// OK: a quota lookup keyed on the forwarded header is S11, not S10.
public Note quotaByForwardedIp(HttpServletRequest request, String token) {
    Session session = resolveSession(token);
    String fwd = request.getHeader("X-Forwarded-For");
    // ok: mcp-authz-scope-from-request-header-java
    if (repo.getQuotaCount(fwd) >= 10) throw new IllegalStateException("quota");
    return repo.listNotesByOrg(session.getOrgId());
}

class Session {
    String getOrgId() { return ""; }
    String getClientIp() { return ""; }
}
interface Repo {
    Mono<Note> listNotesByOrg(String orgId);
    Mono<Note> listNotesForClientIp(String ip);
    Mono<Note> findNoteBy(String id, String orgId);
}
class Note {}
interface Logger { void info(String msg, Object... args); }
Logger logger = null;