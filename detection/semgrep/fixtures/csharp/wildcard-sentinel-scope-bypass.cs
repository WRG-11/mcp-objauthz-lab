// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass-csharp
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

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

// FIRE: wildcard comparison gates returning all orgs' data (authz bypass)
public async Task<IEnumerable<Note>> VulnExport(string token, string org_id) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    if (org_id == "*" || org_id == "all") {
        return await _repo.Notes.ToListAsync();
    }
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// FIRE: ternary with wildcard selecting all-orgs vs scoped data (authz bypass)
public async Task<IEnumerable<Note>> VulnExportTernary(string token, string org_id) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    return org_id == "*" 
        ? await _repo.Notes.ToListAsync() 
        : await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// FIRE: wildcard check skips normal org scoping (authz bypass)
public async Task<IEnumerable<Note>> VulnExportSkipScope(string token, string org_id) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    if (org_id == "*") {
        return await _repo.Notes.ToListAsync();
    }
    // no org scoping in this branch -- wildcard bypassed it
    return await _repo.Notes.ToListAsync();
}

// OK: wildcard guarded by admin role check
public async Task<IEnumerable<Note>> FixedExportGuarded(string token, string org_id) {
    var session = ResolveSession(token);
    RequireAdminRole(session);
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (org_id == "*" || org_id == "all") {
        return await _repo.Notes.ToListAsync();
    }
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// SILENT: wildcard in markup rendering (textual, not authz)
// The parameter name matches scope regex but context is markup, not authz
public string RenderMarkdown(string text) {
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    return System.Text.RegularExpressions.Regex.Replace(text, @"\*(.+?)\*", "<b>$1</b>");
}

// SILENT: wildcard in UI search filter (textual comparison, not authz)
// The variable name matches scope regex but it's a UI filter value, not scope
public IEnumerable<Note> FilterNotesByScope(IEnumerable<Note> notes, string scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (scope == "all") {
        return notes; // UI "show all" filter, not authz bypass
    }
    return notes.Where(n => n.Scope == scope);
}

// SILENT: wildcard in logging (textual, not authz)
public void LogScopeValue(string scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (scope == "*") {
        _logger.LogInformation("wildcard scope requested");
    }
}

class Session { public string OrgId { get; set; } = ""; }
class Note { public string Id { get; set; } = ""; public string OrgId { get; set; } = ""; public string Scope { get; set; } = ""; }
interface IRepository { 
    System.Collections.Generic.IEnumerable<Note> Notes { get; }
    Task<List<Note>> ToListAsync();
    IQueryable<Note> Where(System.Linq.Expressions.Expression<Func<Note, bool>> predicate);
}
interface ILogger { void LogInformation(string message, params object[] args); }

Session ResolveSession(string token) => new Session();
void RequireAdminRole(Session session) {}
IRepository _repo = null;
ILogger _logger = null;