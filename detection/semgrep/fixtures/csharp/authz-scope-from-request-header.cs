// Test fixture for rule: mcp-authz-scope-from-request-header-csharp
//
// S10 (forwarded-header-as-scope). ASP.NET Core MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// Corpus signatures (5 total, all POOL - TrashMobMCP, TrashMob):
// - TrashMobMCP/ApiKeyAuthMiddleware: context.Request.Headers.TryGetValue(ApiKeyHeaderName, out var headerValue) → auth
// - TrashMob/ChannelKeyAuthenticationFilter: context.HttpContext.Request.Headers.TryGetValue("IFTTT-Channel-Key", out var iftttChannelKeyRequest) → auth
// - TrashMob/WaiversV2Controller: Request.Headers["X-Forwarded-For"].ToString() → spoofable header in decision
// - TrashMob/CorrelationIdMiddleware: context.Request.Headers[CorrelationIdHeader].ToString() (SILENT: tracing)
// - TrashMob/PrivoApiKeyAuthenticationFilter: context.HttpContext.Request.Headers.TryGetValue(ApiKeyHeaderName, out var apiKeyHeader) → auth
//
// Two-way canary axis: is the header read (inbound, for a decision) or written (outbound) /
// read for a non-authz concern (locale, tracing, negotiation)? (write or non-authz ⇒ SILENT)

using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

// FIRE: Request.Headers["X-Forwarded-For"] / .TryGetValue(ApiKeyHeaderName, ...) used to authenticate/scope
public async Task<IEnumerable<Note>> NoteGetScopedVuln(HttpRequest request, string token) {
    var session = ResolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-csharp
    var headerOrg = request.Headers["x-org-id"].FirstOrDefault() ?? session.OrgId;
    return await _repo.Notes.Where(n => n.OrgId == headerOrg).ToListAsync();
}

// FIRE: TryGetValue with authz decision
public async Task<IEnumerable<Note>> NoteGetScopedTryGetValueVuln(HttpRequest request, string token) {
    var session = ResolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-csharp
    if (request.Headers.TryGetValue("X-Org-Id", out var headerOrgVal)) {
        var headerOrg = headerOrgVal.FirstOrDefault();
        return await _repo.Notes.Where(n => n.OrgId == headerOrg).ToListAsync();
    }
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
public async Task<IEnumerable<Note>> NoteGetScopedByIpVuln(HttpRequest request, string token) {
    var session = ResolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-csharp
    var fwd = request.Headers["x-forwarded-for"].FirstOrDefault() ?? session.ClientIp;
    return await _repo.Notes.Where(n => n.ClientIp == fwd).ToListAsync();
}

// FIRE: header used directly as OrgId in a query filter (authz decision)
public async Task<Note> NoteGetByQueryVuln(HttpRequest request, string token, string id) {
    var session = ResolveSession(token);
    // ruleid: mcp-authz-scope-from-request-header-csharp
    var headerOrg = request.Headers["x-org-id"].FirstOrDefault() ?? session.OrgId;
    return await _repo.Notes.FirstOrDefaultAsync(n => n.Id == id && n.OrgId == headerOrg);
}

// OK: scope comes from the session; no header is consulted at all.
public async Task<IEnumerable<Note>> NoteGetScopedFixed(HttpRequest request, string token) {
    var session = ResolveSession(token);
    // ok: mcp-authz-scope-from-request-header-csharp
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// OK (legitimate neighbor): a non-scope header read for logging only.
public void LogRequest(HttpRequest request) {
    // ok: mcp-authz-scope-from-request-header-csharp
    var reqId = request.Headers["x-request-id"].FirstOrDefault();
    _logger.LogInformation("tool invoked, reqId={ReqId}", reqId);
}

// SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
// This is the two-way canary: reading XFF for logging must NOT fire.
public void LogClientIp(HttpRequest request) {
    // ok: mcp-authz-scope-from-request-header-csharp
    var clientIp = request.Headers["x-forwarded-for"].FirstOrDefault();
    _logger.LogInformation("rate-limit check, clientIp={ClientIp}", clientIp);
}

// SILENT: scope-shaped header read into a variable but NEVER used for authz
public async Task<IEnumerable<Note>> ReadHeaderButDontUse(HttpRequest request, string token) {
    var session = ResolveSession(token);
    // ok: mcp-authz-scope-from-request-header-csharp
    var _unused = request.Headers["x-org-id"].FirstOrDefault();
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// SILENT: outbound write on HttpRequestMessage — request.Headers.Add("Accept", ...) / request.Headers.Authorization = ...
public void OutboundWrite(System.Net.Http.HttpRequestMessage request) {
    // ok: mcp-authz-scope-from-request-header-csharp
    request.Headers.Add("Accept", "application/json");
    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "token");
}

// SILENT: header read for tracing (User-Agent, X-Correlation-ID)
public void LogTracing(HttpRequest request) {
    // ok: mcp-authz-scope-from-request-header-csharp
    var ua = request.Headers["User-Agent"].FirstOrDefault();
    var corr = request.Headers["X-Correlation-ID"].FirstOrDefault();
    _logger.LogInformation("ua={UA} corr={Corr}", ua, corr);
}

class Session { public string OrgId { get; set; } = ""; public string ClientIp { get; set; } = ""; }
class Note { public string Id { get; set; } = ""; public string OrgId { get; set; } = ""; public string ClientIp { get; set; } = ""; }
interface IRepository { 
    System.Collections.Generic.IEnumerable<Note> Notes { get; }
}
interface ILogger { void LogInformation(string message, params object[] args); }

Session ResolveSession(string token) => new Session();
IRepository _repo = null;
ILogger _logger = null;