<?php
// Test fixture for rule: mcp-wildcard-sentinel-scope-bypass-php
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
function vulnExport(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    if ($org_id === "*" || $org_id === "all") {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

// FIRE: ternary with wildcard selecting all-orgs vs scoped data (authz bypass)
function vulnExportTernary(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    return $org_id === "*" ? Note::all() : Note::where('org_id', $session->org_id)->get();
}

// FIRE: wildcard check skips normal org scoping (authz bypass)
function vulnExportSkipScope(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    if ($org_id === "*") {
        return Note::all();
    }
    // no org scoping in this branch -- wildcard bypassed it
    return Note::all();
}

// OK: wildcard guarded by admin role check
function fixedExportGuarded(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    requireAdminRole($session);
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($org_id === "*" || $org_id === "all") {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

// SILENT: wildcard in markup rendering (textual, not authz)
// The parameter name matches scope regex but context is markup, not authz
function renderMarkdown(string $text): string {
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    return preg_replace('/\*(.+?)\*/', '<b>$1</b>', $text);
}

// SILENT: wildcard in UI search filter (textual comparison, not authz)
// The variable name matches scope regex but it's a UI filter value, not scope
function filterNotesByScope(array $notes, string $scope): array {
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($scope === "all") {
        return $notes; // UI "show all" filter, not authz bypass
    }
    return array_filter($notes, fn($n) => $n['scope'] === $scope);
}

// SILENT: wildcard in logging (textual, not authz)
function logScopeValue(string $scope): void {
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($scope === "*") {
        logger()->info('wildcard scope requested');
    }
}

function resolveSession(string $token): object { return new class { public $org_id = ''; }; }
function requireAdminRole(object $session): void {}
function logger(): \Psr\Log\LoggerInterface { return new class implements \Psr\Log\LoggerInterface { public function log($level, $message, array $context = []): void {} }; }
class Note extends \Illuminate\Database\Eloquent\Model {
    public static function all(): \Illuminate\Database\Eloquent\Collection { return new \Illuminate\Database\Eloquent\Collection(); }
    public static function where(string $column, mixed $value): \Illuminate\Database\Eloquent\Builder { return new \Illuminate\Database\Eloquent\Builder(null); }
}