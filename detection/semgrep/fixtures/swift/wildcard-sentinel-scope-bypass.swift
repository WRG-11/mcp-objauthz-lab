// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass-swift
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

import Vapor
import Fluent

// FIRE: wildcard comparison gates returning all orgs' data (authz bypass)
func vulnExport(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" || org_id == "all" {
        return try await Note.query(on: req.db).all()
    }
    return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// FIRE: ternary with wildcard selecting all-orgs vs scoped data (authz bypass)
func vulnExportTernary(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-swift
    return org_id == "*" 
        ? try await Note.query(on: req.db).all()
        : try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// FIRE: wildcard check skips normal org scoping (authz bypass)
func vulnExportSkipScope(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" {
        return try await Note.query(on: req.db).all()
    }
    // no org scoping in this branch -- wildcard bypassed it
    return try await Note.query(on: req.db).all()
}

// OK: wildcard guarded by admin role check
func fixedExportGuarded(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    try requireAdminRole(req: req, session: session)
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" || org_id == "all" {
        return try await Note.query(on: req.db).all()
    }
    return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// SILENT: wildcard in markup rendering (textual, not authz)
// The parameter name matches scope regex but context is markup, not authz
func renderMarkdown(_ text: String) -> String {
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    return text.replacingOccurrences(of: "\\*(.+?)\\*", with: "<b>$1</b>", options: .regularExpression)
}

// SILENT: wildcard in UI search filter (textual comparison, not authz)
// The variable name matches scope regex but it's a UI filter value, not scope
func filterNotesByScope(_ notes: [Note], scope: String) -> [Note] {
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if scope == "all" {
        return notes // UI "show all" filter, not authz bypass
    }
    return notes.filter { $0.scope == scope }
}

// SILENT: wildcard in logging (textual, not authz)
func logScopeValue(_ scope: String, req: Request) {
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if scope == "*" {
        req.logger.info("wildcard scope requested")
    }
}

// FIRE: the "all" spelling alone.
func vulnExportAll(req: Request, token: String, tenant: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-swift
    if tenant == "all" {
        return try await Note.query(on: req.db).all()
    }
    return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// FIRE: the "all" spelling of the ternary.
func vulnExportTernaryAll(req: Request, token: String, tenant: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ruleid: mcp-wildcard-sentinel-scope-bypass-swift
    return tenant == "all"
        ? try await Note.query(on: req.db).all()
        : try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// TODO: the Swift parser groups `a == "*" || flag` as `a == ("*" || flag)`,
// so the comparison is not a subexpression and the rule does not see it.
// Only the last comparison of a `||` chain is reliably found.
func vulnExportVerbose(req: Request, token: String, org_id: String, verbose: Bool) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // todoruleid: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" || verbose {
        return try await Note.query(on: req.db).all()
    }
    return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// OK: the wildcard branch still filters by the session's org. Pins the
// filterless-query receiver filter.
func exportOwnOrg(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" {
        return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
    }
    return []
}

// OK: guarded by checkAdminRole. Pins that guard.
func fixedExportChecked(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    try checkAdminRole(req: req, session: session)
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" {
        return try await Note.query(on: req.db).all()
    }
    return []
}

// OK: guarded by assertAdminRole. Pins that guard.
func fixedExportAsserted(req: Request, token: String, org_id: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    try assertAdminRole(req: req, session: session)
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if org_id == "*" {
        return try await Note.query(on: req.db).all()
    }
    return []
}

// OK: "all" on an export format, not a scope. Pins the parameter-name regex
// of both forms.
func exportFields(req: Request, format: String) async throws -> [Field] {
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    if format == "all" {
        return try await Field.query(on: req.db).all()
    }
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    return format == "*" ? try await Field.query(on: req.db).all() : []
}

// OK: a ternary that picks a CSS class. Pins the string-literal exclusion.
func filterButtonClass(scope: String) -> String {
    // ok: mcp-wildcard-sentinel-scope-bypass-swift
    return scope == "all" ? "active" : ""
}

struct Session { let orgId: String }
final class Note: Model, @unchecked Sendable {
    static let schema = "notes"
    @ID(key: .id) var id: UUID?
    @Field(key: "org_id") var orgId: String
    @Field(key: "scope") var scope: String
    init() {}
}
func resolveSession(req: Request, token: String) async throws -> Session { return Session(orgId: "") }
func requireAdminRole(req: Request, session: Session) async throws {}