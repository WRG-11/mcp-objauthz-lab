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

// FIRE: the "all" spelling alone.
function vulnExportAll(string $token, string $tenant): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    if ($tenant === "all") {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

// FIRE: the literal-first spellings.
function vulnExportLiteralFirst(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    if ("*" === $org_id) {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

function vulnExportLiteralFirstAll(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    if ("all" === $org_id) {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

// FIRE: the "all" spelling of the ternary.
function vulnExportTernaryAll(string $token, string $tenant): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-wildcard-sentinel-scope-bypass-php
    return $tenant === "all" ? Note::all() : Note::where('org_id', $session->org_id)->get();
}

// OK: `all()` on a collection the caller already holds is not a model read.
// Pins the model-class filter.
function flattenScoped(array $groups, string $scope): array {
    $notes = collect($groups);
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($scope === "*") {
        return $notes->all();
    }
    return [];
}

// OK: a static call on a class that reads nothing (the Log facade). Pins the
// list-all method regex.
function auditScope(string $scope): void {
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($scope === "*") {
        Log::info('wildcard scope requested');
    }
}

// OK: guarded by checkAdminRole. Pins that guard.
function fixedExportChecked(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    checkAdminRole($session);
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($org_id === "*") {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

// OK: guarded by assertAdminRole. Pins that guard.
function fixedExportAsserted(string $token, string $org_id): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    assertAdminRole($session);
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($org_id === "*") {
        return Note::all();
    }
    return Note::where('org_id', $session->org_id)->get();
}

// OK: "all" on an export format, not a scope. Pins the parameter-name regex
// of both forms.
function exportFields(string $format): array {
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    if ($format === "all") {
        return Field::all();
    }
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    return $format === "*" ? Field::all() : Field::defaults();
}

// OK: a ternary that picks a CSS class. Pins the string-literal exclusion.
function filterButtonClass(string $scope): string {
    // ok: mcp-wildcard-sentinel-scope-bypass-php
    return $scope === "all" ? 'active' : '';
}

function resolveSession(string $token): object { return new class { public $org_id = ''; }; }
function requireAdminRole(object $session): void {}
function logger(): \Psr\Log\LoggerInterface { return new class implements \Psr\Log\LoggerInterface { public function log($level, $message, array $context = []): void {} }; }
class Note extends \Illuminate\Database\Eloquent\Model {
    public static function all(): \Illuminate\Database\Eloquent\Collection { return new \Illuminate\Database\Eloquent\Collection(); }
    public static function where(string $column, mixed $value): \Illuminate\Database\Eloquent\Builder { return new \Illuminate\Database\Eloquent\Builder(null); }
}