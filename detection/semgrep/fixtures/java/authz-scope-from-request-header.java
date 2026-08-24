// Test fixture for rule: mcp-authz-scope-from-request-header-java
//
// S10 (forwarded-header-as-scope). Spring/WebFlux MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// TWO-WAY CANARY:
// - FIRE: header value feeds an authz decision (scope/org-id selection, listNotesByOrg(headerValue))
// - SILENT: header read ONLY for logging (no authz decision)

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

// FIRE: header value used to select org scope in a repository call (authz decision)
public Mono<Note> noteGetScopedVuln(ServerWebExchange exchange, String token) {
    Session session = resolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-java
    String headerOrg = exchange.getRequest().getHeaders().getFirst("x-org-id") != null 
        ? exchange.getRequest().getHeaders().getFirst("x-org-id") 
        : session.getOrgId();
    return repo.listNotesByOrg(headerOrg);
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
public Mono<Note> noteGetScopedByIpVuln(ServerWebExchange exchange, String token) {
    Session session = resolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-java
    String fwd = exchange.getRequest().getHeaders().getFirst("x-forwarded-for") != null
        ? exchange.getRequest().getHeaders().getFirst("x-forwarded-for")
        : session.getClientIp();
    return repo.listNotesForClientIp(fwd);
}

// FIRE: header used directly as orgId in a query filter (authz decision)
public Mono<Note> noteGetByQueryVuln(ServerWebExchange exchange, String token, String id) {
    Session session = resolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-java
    String headerOrg = exchange.getRequest().getHeaders().getFirst("x-org-id") != null
        ? exchange.getRequest().getHeaders().getFirst("x-org-id")
        : session.getOrgId();
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