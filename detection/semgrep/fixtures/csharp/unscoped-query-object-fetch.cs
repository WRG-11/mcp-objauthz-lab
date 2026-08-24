// Test fixture for rule: mcp-unscoped-query-object-fetch-csharp
//
// The query-scoped shape: an EF Core fetch where the tenant key is either
// present in the query (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

// FIRE: Find by id only (no tenant key)
public async Task<Credential> GetCredentialVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _context.Credentials.FindAsync(id);
}

// OK: Find by id with tenant key
public async Task<Credential> GetCredentialSafe(string id, string workspaceId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Credentials
        .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);
}

// FIRE: FirstOrDefault with only id
public async Task<Note> GetNoteVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes.FirstOrDefaultAsync(n => n.Id == id);
}

// OK: FirstOrDefault with orgId
public async Task<Note> GetNoteSafe(string id, string orgId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes
        .FirstOrDefaultAsync(n => n.Id == id && n.OrgId == orgId);
}

// FIRE: Remove with Find only
public async Task DeleteRecordVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    var entity = await _context.Notes.FindAsync(id);
    if (entity != null) _context.Notes.Remove(entity);
}

// OK: Remove with tenant key
public async Task DeleteRecordSafe(string id, string projectId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    var entity = await _context.Notes
        .FirstOrDefaultAsync(n => n.Id == id && n.ProjectId == projectId);
    if (entity != null) _context.Notes.Remove(entity);
}

class Credential { public string Id { get; set; } = ""; public string WorkspaceId { get; set; } = ""; }
class Note { public string Id { get; set; } = ""; public string OrgId { get; set; } = ""; public string ProjectId { get; set; } = ""; }
class AppDbContext : DbContext {
    public DbSet<Credential> Credentials { get; set; }
    public DbSet<Note> Notes { get; set; }
}
AppDbContext _context = null;