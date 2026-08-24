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
    if let credential = try await Credential.find(id, on: req.db) {
        try await credential.delete(on: req.db)
    }
}

// OK: delete with projectId
func deleteRecordSafe(req: Request, id: UUID, projectId: String) async throws {
    // ok: mcp-unscoped-query-object-fetch-swift
    if let note = try await Note.query(on: req.db)
        .filter(\.$id == id)
        .filter(\.$projectId == projectId)
        .first() {
        try await note.delete(on: req.db)
    }
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