// Test fixture for rule: mcp-unscoped-query-object-fetch-csharp
//
// The query-scoped shape: an EF Core fetch where the tenant key is either
// present in the query (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.
//
// Corpus signatures (5 total, all POOL):
// - daohainam/microservice-patterns: BookService Books.FindAsync(id)
// - daohainam/microservice-patterns: PaymentService Cards.FindAsync(id)
// - Azure-Samples/eShopLite 06-mcp: MemoryContext db.FindAsync<Product>(id) ← MCP server
// - TrashMob: SyncQueue db.FindAsync<PendingRouteSession>(sessionId)
// - (variant) FirstOrDefaultAsync also present as by-id fetch in same repos
//
// Two-way canary axis: is the fetch narrowed by an owner/tenant? (present ⇒ SILENT)

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

// FIRE: Find by id only (no tenant key) — EF Core DbSet.FindAsync / DbContext.FindAsync
public async Task<Credential> GetCredentialVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _context.Credentials.FindAsync(id);
}

// FIRE: DbContext.FindAsync<T>(id) — eShopLite 06-mcp pattern
public async Task<Product> GetProductVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _context.FindAsync<Product>(id);
}

// FIRE: FirstOrDefault with only id
public async Task<Note> GetNoteVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes.FirstOrDefaultAsync(n => n.Id == id);
}

// FIRE: SingleOrDefault with only id
public async Task<Note> GetNoteSingleVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes.SingleOrDefaultAsync(n => n.Id == id);
}

// FIRE: Remove with Find only
public async Task DeleteRecordVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    var entity = await _context.Notes.FindAsync(id);
    if (entity != null) _context.Notes.Remove(entity);
}

// OK: Find by id with tenant key in predicate (SILENT - owner/tenant scoped)
public async Task<Credential> GetCredentialSafe(string id, string workspaceId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Credentials
        .FirstOrDefaultAsync(c => c.Id == id && c.WorkspaceId == workspaceId);
}

// OK: FirstOrDefault with orgId
public async Task<Note> GetNoteSafe(string id, string orgId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes
        .FirstOrDefaultAsync(n => n.Id == id && n.OrgId == orgId);
}

// OK: Remove with tenant key
public async Task DeleteRecordSafe(string id, string projectId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    var entity = await _context.Notes
        .FirstOrDefaultAsync(n => n.Id == id && n.ProjectId == projectId);
    if (entity != null) _context.Notes.Remove(entity);
}

// SILENT: Where clause carries tenant — .Where(x => x.OrgId == orgId).FirstOrDefaultAsync(x => x.Id == id)
public async Task<Note> GetNoteWhereSafe(string id, string orgId) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes
        .Where(x => x.OrgId == orgId)
        .FirstOrDefaultAsync(x => x.Id == id);
}

class Credential { public string Id { get; set; } = ""; public string WorkspaceId { get; set; } = ""; }
class Product { public string Id { get; set; } = ""; public string TenantId { get; set; } = ""; }
class Note { public string Id { get; set; } = ""; public string OrgId { get; set; } = ""; public string ProjectId { get; set; } = ""; public string TenantId { get; set; } = ""; }
class AppDbContext : DbContext {
    public DbSet<Credential> Credentials { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<Note> Notes { get; set; }
}
AppDbContext _context = null;