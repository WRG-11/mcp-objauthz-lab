// Test fixture for rule: mcp-authz-scope-from-request-header-swift
//
// S10 (forwarded-header-as-scope). Vapor/SwiftNIO MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// TWO-WAY CANARY:
// - FIRE: header value feeds an authz decision (scope/org-id selection, Note.query(\.orgId == headerValue))
// - SILENT: header read ONLY for logging (no authz decision)
//
// The rule is a taint rule, so a finding sits on the SINK: the value in the
// scope filter, or the finder call. `ruleid:` markers are above that line.

import Vapor
import Fluent

// FIRE: header value used to select org scope in a Fluent query (authz decision)
func noteGetScopedVuln(req: Request, token: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    let headerOrg = req.headers["x-org-id"].first ?? session.orgId
    // ruleid: mcp-authz-scope-from-request-header-swift
    return try await Note.query(on: req.db).filter(\.$orgId == headerOrg).all()
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
func noteGetScopedByIpVuln(req: Request, token: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    let fwd = req.headers["x-forwarded-for"].first ?? session.clientIp
    // ruleid: mcp-authz-scope-from-request-header-swift
    return try await Note.query(on: req.db).filter(\.$clientIp == fwd).all()
}

// FIRE: header used directly as orgId in a query filter (authz decision)
func noteGetByQueryVuln(req: Request, token: String, id: String) async throws -> Note? {
    let session = try resolveSession(req: req, token: token)
    let headerOrg = req.headers["x-org-id"].first ?? session.orgId
    return try await Note.query(on: req.db)
        .filter(\.$id == id)
        // ruleid: mcp-authz-scope-from-request-header-swift
        .filter(\.$orgId == headerOrg)
        .first()
}

// OK: scope comes from the session; no header is consulted at all.
func noteGetScopedFixed(req: Request, token: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ok: mcp-authz-scope-from-request-header-swift
    return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// OK (legitimate neighbor): a non-scope header read for logging only.
func logRequest(req: Request) {
    // ok: mcp-authz-scope-from-request-header-swift
    let reqId = req.headers["x-request-id"].first
    req.logger.info("tool invoked, reqId=\(reqId ?? "none")")
}

// SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
// This is the two-way canary: reading XFF for logging must NOT fire.
func logClientIp(req: Request) {
    // ok: mcp-authz-scope-from-request-header-swift
    let clientIp = req.headers["x-forwarded-for"].first
    req.logger.info("rate-limit check, clientIp=\(clientIp ?? "none")")
}

// SILENT: scope-shaped header read into a variable but NEVER used for authz
func readHeaderButDontUse(req: Request, token: String) async throws -> [Note] {
    let session = try resolveSession(req: req, token: token)
    // ok: mcp-authz-scope-from-request-header-swift
    let _unused = req.headers["x-org-id"].first
    return try await Note.query(on: req.db).filter(\.$orgId == session.orgId).all()
}

// FIRE: headers.first(name:) feeding a tenant filter.
func projectListVuln(req: Request) async throws -> [Project] {
    let tenant = req.headers.first(name: "X-Tenant-Id") ?? ""
    // ruleid: mcp-authz-scope-from-request-header-swift
    return try await Project.query(on: req.db).filter(\.$tenantId == tenant).all()
}

// FIRE: finder keyed by the header value.
func accountShowVuln(req: Request) async throws -> Account? {
    // The finder also has no tenant key, so the S7 rule fires as well.
    // ruleid: mcp-unscoped-query-object-fetch-swift
    // ruleid: mcp-authz-scope-from-request-header-swift
    return try await Account.find(req.headers["x-account-id"].first, on: req.db)
}

// OK (legitimate neighbor): a correlation header as a finder key is not a
// scope header. Pins the header-name regex of the subscript source.
func auditShow(req: Request) async throws -> AuditEvent? {
    // The finder also has no tenant key, so the S7 rule fires as well.
    // ruleid: mcp-unscoped-query-object-fetch-swift
    // ok: mcp-authz-scope-from-request-header-swift
    return try await AuditEvent.find(req.headers["x-request-id"].first, on: req.db)
}

// OK: the same through headers.first(name:). Pins its header-name regex.
func auditShowFirst(req: Request) async throws -> AuditEvent? {
    // The finder also has no tenant key, so the S7 rule fires as well.
    // ruleid: mcp-unscoped-query-object-fetch-swift
    // ok: mcp-authz-scope-from-request-header-swift
    return try await AuditEvent.find(req.headers.first(name: "X-Request-Id"), on: req.db)
}

// OK: the header narrows a non-scope key inside the session's org. Pins the
// scope-key regex.
func listEventsFromIp(req: Request, token: String) async throws -> [Event] {
    let session = try await resolveSession(req: req, token: token)
    let clientIp = req.headers["x-forwarded-for"].first ?? ""
    return try await Event.query(on: req.db)
        .filter(\.$orgId == session.orgId)
        // ok: mcp-authz-scope-from-request-header-swift
        .filter(\.$sourceIp == clientIp)
        .all()
}

struct Session { let orgId: String; let clientIp: String }
final class Note: Model, @unchecked Sendable {
    static let schema = "notes"
    @ID(key: .id) var id: UUID?
    @Field(key: "org_id") var orgId: String
    @Field(key: "client_ip") var clientIp: String
    init() {}
}
func resolveSession(req: Request, token: String) async throws -> Session { return Session(orgId: "", clientIp: "") }