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
    // ok: mcp-unscoped-query-object-fetch-csharp
    if (entity != null) _context.Notes.Remove(entity);
}

// FIRE: synchronous Find by id only.
public Note GetNoteSyncVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return _context.Notes.Find(id);
}

// FIRE: a repository wrapper fetched by id only.
public async Task<Note> GetNoteFromRepositoryVuln(string id) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    return await _noteRepository.FindAsync(id);
}

// FIRE: the id is a field of the request body.
public async Task<bool> AckNoteVuln([FromBody] NoteRef m) {
    // ruleid: mcp-unscoped-query-object-fetch-csharp
    var note = await _context.Notes.FindAsync(m.Id);
    return note != null;
}

// OK: the id comes from the caller's claims, not from the request. Pins the
// rule that the id must come from a parameter.
public async Task<Note> GetPinnedNoteFromClaims(CancellationToken ct) {
    var pinned = User.FindFirst("pinned_note")?.Value;
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes.FindAsync(pinned);
}

// OK: a private helper that receives a loaded row. Pins the `public`
// restriction.
private async Task<Note> LoadParentNote(Note child) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes.FindAsync(child.ParentId);
}

// OK: a repository write is not a fetch. Pins the method regex of the
// repository branch.
public async Task SaveNote(Note note) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    await _noteRepository.Add(note);
}

// OK: a count returns no row. Pins the First/Single method regex.
public async Task<int> CountNotesById(string id) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _context.Notes.CountAsync(n => n.Id == id);
}

// OK: a lookup that is not a repository or a DbSet. Pins the repository
// receiver regex.
public async Task<Note> GetFromLookup(string id) {
    // ok: mcp-unscoped-query-object-fetch-csharp
    return await _lookup.FindAsync(id);
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

class NoteRef { public string Id { get; set; } = ""; }
class Credential { public string Id { get; set; } = ""; public string WorkspaceId { get; set; } = ""; }
class Product { public string Id { get; set; } = ""; public string TenantId { get; set; } = ""; }
class Note { public string Id { get; set; } = ""; public string OrgId { get; set; } = ""; public string ProjectId { get; set; } = ""; public string TenantId { get; set; } = ""; }
class AppDbContext : DbContext {
    public DbSet<Credential> Credentials { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<Note> Notes { get; set; }
    public AppDbContext _context = null;
}