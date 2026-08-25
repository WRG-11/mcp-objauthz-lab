<?php
// Test fixture for rule: mcp-unscoped-query-object-fetch-php
//
// The query-scoped shape: a model/repo fetch where the tenant key is either
// present in the query (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.
//
// Corpus signatures (4 total):
// - POOL Contao/ProcessWire: ArticleModel::findBy(['id=?'], [$toolInputId])
// - POOL Contao: find(string $type, string $id, ...) MCP tool takes raw $id
// - POOL ProcessWire: findPages(array $input) MCP tool
// - ECO Eloquent: User::find($request->id), Team::findOrFail($id) — confirmed in ecosystem only
//
// NOTE: PHP MCP pool uses Contao Models (Model::findBy) and ProcessWire selectors,
// NOT Laravel Eloquent. Eloquent find/findOrFail is confirmed only in ecosystem.
// Pattern BOTH families.
//
// Two-way canary axis: is a tenant/owner column in the criteria? (present ⇒ SILENT)

use Illuminate\Database\Eloquent\Model;

// FIRE: Eloquent find by id only (ecosystem)
function getCredentialVuln(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Credential::find($id);
}

// FIRE: Eloquent findOrFail by id only (ecosystem)
function getCredentialVulnFail(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Credential::findOrFail($id);
}

// FIRE: Contao findByPk (POOL)
function getContaoVuln(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return ArticleModel::findByPk($id);
}

// FIRE: Contao findBy with id-only criteria (POOL - MCP tool)
function getContaoFindByVuln(array $input): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    $id = $input['id'] ?? '';
    return ArticleModel::findBy(['id=?'], [$id]);
}

// FIRE: ProcessWire findPages (POOL - MCP tool takes raw id/selector)
function getProcessWireVuln(array $input): array {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return PagesTools::findPages($input);
}

// FIRE: Doctrine find by id (if Doctrine repo)
function getDoctrineVuln(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return $repo->find($id);
}

// OK: Eloquent where with tenant key (SILENT - ecosystem)
function getCredentialSafe(string $id, string $workspace_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return Credential::where('id', $id)->where('workspace_id', $workspace_id)->first();
}

// OK: Contao findOneBy with tenant column (SILENT)
function getContaoSafe(string $id, string $tenant_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return ArticleModel::findOneBy(['id' => $id, 'tenant_id' => $tenant_id]);
}

// OK: Eloquent whereBelongsTo (SILENT - spatie/laravel-query-builder pattern)
function getNoteBelongsTo(string $id, $owner): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return Note::whereBelongsTo($owner)->where('id', $id)->first();
}

// OK: Doctrine with tenant criteria
function getDoctrineSafe(string $id, string $tenant_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return $repo->findOneBy(['id' => $id, 'tenant_id' => $tenant_id]);
}

// SILENT: Eloquent destroy with tenant check
function deleteRecordSafe(string $id, string $project_id): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    $note = Note::where('id', $id)->where('project_id', $project_id)->first();
    return $note ? $note->delete() : null;
}

class Credential extends Model { }
class Note extends Model { }
class ArticleModel extends Model { 
    public static function findBy($cols, $vals) { return null; }
    public static function findByPk($id) { return null; }
    public static function findOneBy(array $criteria) { return null; }
}
class PagesTools { 
    public static function findPages(array $input) { return []; }
}
$repo = null;