// Test fixture for rule: mcp-unscoped-query-object-fetch-swift
//
// The query-scoped shape: a Fluent fetch where the tenant key is either
// present in the query (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.

import Vapor
import Fluent

// FIRE: find by id only (no tenant key)
func getCredentialVuln(req: Request, id: UUID) async throws -> Credential? {
    // ruleid: mcp-unscoped-query-object-fetch-swift
    return try await Credential.find(id, on: req.db)
}

// OK: find by id with tenant key
func getCredentialSafe(req: Request, id: UUID, workspaceId: String) async throws -> Credential? {
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await Credential.query(on: req.db)
        .filter(\.$id == id)
        .filter(\.$workspaceId == workspaceId)
        .first()
}

// FIRE: query with only id
func getNoteVuln(req: Request, id: UUID) async throws -> Note? {
    // ruleid: mcp-unscoped-query-object-fetch-swift
    return try await Note.query(on: req.db).filter(\.$id == id).first()
}

// OK: query with orgId
func getNoteSafe(req: Request, id: UUID, orgId: String) async throws -> Note? {
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await Note.query(on: req.db)
        .filter(\.$id == id)
        .filter(\.$orgId == orgId)
        .first()
}

// FIRE: delete with only id
func deleteRecordVuln(req: Request, id: UUID) async throws {
    // ruleid: mcp-unscoped-query-object-fetch-swift
    let credential = try await Credential.find(id, on: req.db)
    if let credential = credential {
        try await credential.delete(on: req.db)
    }
}

// OK: delete with projectId
func deleteRecordSafe(req: Request, id: UUID, projectId: String) async throws {
    // ok: mcp-unscoped-query-object-fetch-swift
    let note = try await Note.query(on: req.db)
        .filter(\.$id == id)
        .filter(\.$projectId == projectId)
        .first()
    if let note = note {
        try await note.delete(on: req.db)
    }
}

// FIRE: delete through a query filtered by id only.
func deleteNoteVuln(req: Request, id: UUID) async throws {
    // ruleid: mcp-unscoped-query-object-fetch-swift
    try await Note.query(on: req.db).filter(\.$id == id).delete()
}

// FIRE: a closure route; the id is the route parameter.
func routes(_ app: Application) throws {
    app.get("notes", ":id") { req async throws -> Note in
        // ruleid: mcp-unscoped-query-object-fetch-swift
        guard let note = try await Note.find(req.parameters.get("id"), on: req.db) else {
            throw Abort(.notFound)
        }
        return note
    }
}

// OK: the id comes from the authenticated user. Pins the req.auth sanitizer.
func myNote(req: Request) async throws -> Note? {
    let user = try req.auth.require(User.self)
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await Note.find(user.pinnedNoteID, on: req.db)
}

// OK: the same through the optional req.auth.get. Pins that sanitizer.
func myNoteIfSignedIn(req: Request) async throws -> Note? {
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await Note.find(req.auth.get(User.self)?.pinnedNoteID, on: req.db)
}

// OK: the id is a server constant; only the db handle comes from the request.
// Pins the focus on the id argument.
func welcomeNote(req: Request) async throws -> Note? {
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await Note.find(Note.welcomeID, on: req.db)
}

// OK: an object receiver, not a model class. Pins the class-name filter.
func cachedNote(req: Request, id: UUID) async throws -> Note? {
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await cache.find(id, on: req.db)
}

// OK: a query through the parent relation is scoped to that parent. Pins the
// query-chain text filter.
func myNoteByID(req: Request, id: UUID) async throws -> Note? {
    let user = try req.auth.require(User.self)
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await user.$notes.query(on: req.db).filter(\.$id == id).first()
}

// OK: a lookup by slug is not a by-id fetch; this rule covers the id key only.
// Pins the id filter inside the chain.
func noteBySlug(req: Request, slug: String) async throws -> Note? {
    // ok: mcp-unscoped-query-object-fetch-swift
    return try await Note.query(on: req.db).filter(\.$slug == slug).first()
}

final class Credential: Model, @unchecked Sendable {
    static let schema = "credentials"
    @ID(key: .id) var id: UUID?
    @Field(key: "workspace_id") var workspaceId: String
    init() {}
}

final class Note: Model, @unchecked Sendable {
    static let schema = "notes"
    @ID(key: .id) var id: UUID?
    @Field(key: "org_id") var orgId: String
    @Field(key: "project_id") var projectId: String
    init() {}
}