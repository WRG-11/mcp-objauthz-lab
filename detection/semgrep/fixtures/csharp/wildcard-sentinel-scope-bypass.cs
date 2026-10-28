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

// FIRE: the "all" spelling alone, widening through a list-all repository call.
public async Task<IEnumerable<Note>> VulnExportAll(string token, string tenant) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    if (tenant == "all") {
        return await _notes.GetAllAsync();
    }
    return await _notes.ListByOrgAsync(session.OrgId);
}

// FIRE: the literal-first spellings.
public async Task<IEnumerable<Note>> VulnExportLiteralFirst(string token, string org_id) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    if ("*" == org_id) {
        return _repo.Notes.ToList();
    }
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

public async Task<IEnumerable<Note>> VulnExportLiteralFirstAll(string token, string org_id) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    if ("all" == org_id) {
        return await _repo.Notes.ToArrayAsync();
    }
    return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
}

// FIRE: the "all" spelling of the ternary.
public async Task<IEnumerable<Note>> VulnExportTernaryAll(string token, string tenant) {
    var session = ResolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-csharp
    return tenant == "all" ? _repo.Notes.ToArray() : await _notes.ListByOrgAsync(session.OrgId);
}

// OK: the body narrows by org before loading. Pins the whole-table load shape.
public async Task<IEnumerable<Note>> ExportOwnOrg(string token, string org_id) {
    var session = ResolveSession(token);
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (org_id == "*") {
        return await _repo.Notes.Where(n => n.OrgId == session.OrgId).ToListAsync();
    }
    return new List<Note>();
}

// OK: "*" clears a cache; it reads nothing. Pins the load-method regex.
public void InvalidateCache(string scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (scope == "*") {
        _cache.Notes.Clear();
    }
}

// OK: guarded by CheckAdminRole. Pins that guard.
public async Task<IEnumerable<Note>> FixedExportChecked(string token, string org_id) {
    var session = ResolveSession(token);
    CheckAdminRole(session);
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (org_id == "*") {
        return await _repo.Notes.ToListAsync();
    }
    return new List<Note>();
}

// OK: guarded by AssertAdminRole. Pins that guard.
public async Task<IEnumerable<Note>> FixedExportAsserted(string token, string org_id) {
    var session = ResolveSession(token);
    AssertAdminRole(session);
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (org_id == "*") {
        return await _repo.Notes.ToListAsync();
    }
    return new List<Note>();
}

// OK: "all" on an export format, not a scope. Pins the parameter-name regex
// of both forms.
public async Task<IEnumerable<Field>> ExportFields(string format) {
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    if (format == "all") {
        return await _fields.GetAllAsync();
    }
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    return format == "*" ? _repo.Fields.ToList() : _repo.DefaultFields.ToList();
}

// OK: a ternary that picks a CSS class. Pins the string-literal exclusion.
public string FilterButtonClass(string scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-csharp
    return scope == "all" ? "active" : "";
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