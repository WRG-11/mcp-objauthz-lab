// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass-java
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

// FIRE: wildcard comparison gates returning all orgs' data (authz bypass)
public Mono<Note> vulnExport(String token, String org_id) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    if (org_id.equals("*") || org_id.equals("all")) {
        return repo.listAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

// FIRE: ternary with wildcard selecting all-orgs vs scoped data (authz bypass)
public Mono<Note> vulnExportTernary(String token, String org_id) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    return org_id.equals("*") ? repo.listAllNotes() : repo.listNotesByOrg(session.getOrgId());
}

// FIRE: wildcard check skips normal org scoping (authz bypass)
public Mono<Note> vulnExportSkipScope(String token, String org_id) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    if (org_id.equals("*")) {
        return repo.listAllNotes();
    }
    // no org scoping in this branch -- wildcard bypassed it
    return repo.listAllNotes();
}

// OK: wildcard guarded by admin role check
public Mono<Note> fixedExportGuarded(String token, String org_id) {
    Session session = resolveSession(token);
    requireAdminRole(session);
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    if (org_id.equals("*") || org_id.equals("all")) {
        return repo.listAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

// SILENT: wildcard in markup rendering (textual, not authz)
// The parameter name matches scope regex but context is markup, not authz
public String renderMarkdown(String text) {
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    return text.replaceAll("\\*(.+?)\\*", "<b>$1</b>");
}

// SILENT: wildcard in UI search filter (textual comparison, not authz)
// The variable name matches scope regex but it's a UI filter value, not scope
public List<Note> filterNotesByScope(List<Note> notes, String scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    if (scope.equals("all")) {
        return notes; // UI "show all" filter, not authz bypass
    }
    return notes.stream().filter(n -> n.getScope().equals(scope)).toList();
}

// SILENT: wildcard in logging (textual, not authz)
public void logScopeValue(String scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    if (scope.equals("*")) {
        logger.info("wildcard scope requested");
    }
}

// FIRE: the "all" spelling alone.
public Mono<Note> vulnExportAll(String token, String tenant) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    if (tenant.equals("all")) {
        return repo.listAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

// FIRE: the null-safe literal-first spelling.
public Mono<Note> vulnExportLiteralFirst(String token, String org_id) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    if ("*".equals(org_id)) {
        return repo.listAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

public Mono<Note> vulnExportLiteralFirstAll(String token, String org_id) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    if ("all".equals(org_id)) {
        return repo.findAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

// FIRE: the "all" spelling of the ternary.
public Mono<Note> vulnExportTernaryAll(String token, String tenant) {
    Session session = resolveSession(token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-java
    return tenant.equals("all") ? repo.listAllNotes() : repo.listNotesByOrg(session.getOrgId());
}

// OK: guarded by checkAdminRole. Pins that guard.
public Mono<Note> fixedExportChecked(String token, String org_id) {
    Session session = resolveSession(token);
    checkAdminRole(session);
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    if (org_id.equals("*")) {
        return repo.listAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

// OK: guarded by assertAdminRole. Pins that guard.
public Mono<Note> fixedExportAsserted(String token, String org_id) {
    Session session = resolveSession(token);
    assertAdminRole(session);
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    if (org_id.equals("*")) {
        return repo.listAllNotes();
    }
    return repo.listNotesByOrg(session.getOrgId());
}

// OK: "all" on an export format, not a scope. Pins the parameter-name regex
// of both forms.
public Mono<Note> exportFields(String format) {
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    if (format.equals("all")) {
        return exporter.listAllFields();
    }
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    return format.equals("*") ? exporter.listAllFields() : exporter.defaultFields();
}

// OK: a ternary that picks a CSS class. Pins the string-literal exclusion.
public String filterButtonClass(String scope) {
    // ok: mcp-wildcard-sentinel-scope-bypass-java
    return scope.equals("all") ? "active" : "";
}

Session resolveSession(String token) { return null; }
void requireAdminRole(Session session) {}
interface Repo {
    Mono<Note> listAllNotes();
    Mono<Note> listNotesByOrg(String orgId);
}
class Note { String getScope() { return ""; } }
interface Logger { void info(String msg, Object... args); }
Logger logger = null;