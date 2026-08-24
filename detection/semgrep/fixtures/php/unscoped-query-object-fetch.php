<?php
// Test fixture for rule: mcp-unscoped-query-object-fetch-php
//
// The query-scoped shape: an Eloquent fetch where the tenant key is either
// present in the query (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.

use Illuminate\Database\Eloquent\Model;

// FIRE: find by id only (no tenant key)
function getCredentialVuln(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Credential::find($id);
}

// OK: find by id with tenant key
function getCredentialSafe(string $id, string $workspace_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return Credential::where('id', $id)->where('workspace_id', $workspace_id)->first();
}

// FIRE: where id only
function getNoteVuln(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Note::where('id', $id)->first();
}

// OK: where with org_id
function getNoteSafe(string $id, string $org_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return Note::where('id', $id)->where('org_id', $org_id)->first();
}

// FIRE: destroy with only id
function deleteRecordVuln(string $id): int {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Note::destroy($id);
}

// OK: delete with project_id
function deleteRecordSafe(string $id, string $project_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    $note = Note::where('id', $id)->where('project_id', $project_id)->first();
    return $note ? $note->delete() : null;
}

class Credential extends Model { }
class Note extends Model { }