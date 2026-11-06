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
    $id = $input['id'] ?? '';
    // ruleid: mcp-unscoped-query-object-fetch-php
    return ArticleModel::findBy(['id=?'], [$id]);
}

// TODO: ProcessWire findPages (POOL - MCP tool takes raw id/selector). The
// tool passes a whole selector, not an id; the rule follows ids into by-id
// finders only, so it does not see this shape.
function getProcessWireVuln(array $input): array {
    // todoruleid: mcp-unscoped-query-object-fetch-php
    return PagesTools::findPages($input);
}

// FIRE: Doctrine find by id (if Doctrine repo)
function getDoctrineVuln(string $id, $noteRepository): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return $noteRepository->find($id);
}

// FIRE: Eloquent destroy by id only.
function deleteCredentialVuln(string $id): int {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Credential::destroy($id);
}

// FIRE: Eloquent where('id') with no other key.
function getNoteWhereVuln(string $id): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Note::where('id', $id)->first();
}

// FIRE: plain PHP, id from the query string.
function showNoteFromQuery(): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Note::find($_GET['id']);
}

// FIRE: plain PHP, id from a form post.
function deleteNoteFromForm(): int {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Note::destroy($_POST['note_id']);
}

// FIRE: plain PHP, id from either.
function showCredentialFromRequest(): ?Model {
    // ruleid: mcp-unscoped-query-object-fetch-php
    return Credential::findOrFail($_REQUEST['id']);
}

// OK: the repository is injected as a parameter, but the id comes from the
// session. Pins the focus on the id argument.
function myNote($noteRepository): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return $noteRepository->find(auth()->id());
}

// FIRE: an MCP tool handler method; the id is read out of its input array.
class GetNoteTool {
    public function handle(array $arguments): ?Model {
        $noteId = $arguments['note_id'];
        // ruleid: mcp-unscoped-query-object-fetch-php
        return Note::findOrFail($noteId);
    }
}

// OK: the id comes from the session, not from the caller. Pins the source
// requirement.
function currentProfile(): ?Model {
    $id = auth()->id();
    // ok: mcp-unscoped-query-object-fetch-php
    return Credential::find($id);
}

// OK: the id comes from the signed-in user on the request parameter. The
// request is caller input, but its authenticated user is not. Pins the
// authenticated-user sanitizer.
function myPinnedNote(Request $request): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return Note::find($request->user()->pinned_note_id);
}

// OK: Contao findBy on a parent column lists children; it is not a by-id
// fetch. Pins the id-column criteria.
function listArticles(string $parent): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return ArticleModel::findBy(['pid=?'], [$parent]);
}

// OK: an in-memory cache is not a repository. Pins the receiver regex.
function cachedNote(string $id, $cache): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return $cache->find($id);
}

// OK: a finder that takes a keyed criteria array, inline or built first
// (cron-control's Event::find). Pins the criteria-array sanitizer.
function findPendingEvent(int $timestamp, string $action): ?Model {
    // ok: mcp-unscoped-query-object-fetch-php
    return Event::find(['timestamp' => $timestamp, 'action' => $action]);
}

function findEventByArgs(int $timestamp, string $action): ?Model {
    $query_args = ['timestamp' => $timestamp, 'action' => $action];
    // ok: mcp-unscoped-query-object-fetch-php
    return Event::find($query_args);
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