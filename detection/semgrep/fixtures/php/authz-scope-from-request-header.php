<?php
// Test fixture for rule: mcp-authz-scope-from-request-header-php
//
// S10 (forwarded-header-as-scope). Laravel/Symfony MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// TWO-WAY CANARY:
// - FIRE: header value feeds an authz decision (scope/org-id selection, Note::where('org_id', $headerValue))
// - SILENT: header read ONLY for logging (no authz decision)

use Illuminate\Http\Request;

// FIRE: header value used to select org scope in an Eloquent query (authz decision)
function noteGetScopedVuln(Request $request, string $token): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-authz-scope-from-request-header-php
    $headerOrg = $request->header('x-org-id') ?? $session->org_id;
    return Note::where('org_id', $headerOrg)->get();
}

// FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
function noteGetScopedByIpVuln(Request $request, string $token): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ruleid: mcp-authz-scope-from-request-header-php
    $fwd = $request->header('x-forwarded-for') ?? $session->client_ip;
    return Note::where('client_ip', $fwd)->get();
}

// FIRE: header used directly as org_id in a query filter (authz decision)
function noteGetByQueryVuln(Request $request, string $token, string $id): ?Note {
    $session = resolveSession($token);
    // ruleid: mcp-authz-scope-from-request-header-php
    $headerOrg = $request->header('x-org-id') ?? $session->org_id;
    return Note::where('id', $id)->where('org_id', $headerOrg)->first();
}

// OK: scope comes from the session; no header is consulted at all.
function noteGetScopedFixed(Request $request, string $token): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ok: mcp-authz-scope-from-request-header-php
    return Note::where('org_id', $session->org_id)->get();
}

// OK (legitimate neighbor): a non-scope header read for logging only.
function logRequest(Request $request): void {
    // ok: mcp-authz-scope-from-request-header-php
    $reqId = $request->header('x-request-id');
    logger()->info('tool invoked', ['req_id' => $reqId]);
}

// SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
// This is the two-way canary: reading XFF for logging must NOT fire.
function logClientIp(Request $request): void {
    // ok: mcp-authz-scope-from-request-header-php
    $clientIp = $request->header('x-forwarded-for');
    logger()->info('rate-limit check', ['client_ip' => $clientIp]);
}

// SILENT: scope-shaped header read into a variable but NEVER used for authz
function readHeaderButDontUse(Request $request, string $token): \Illuminate\Database\Eloquent\Collection {
    $session = resolveSession($token);
    // ok: mcp-authz-scope-from-request-header-php
    $_unused = $request->header('x-org-id');
    return Note::where('org_id', $session->org_id)->get();
}

function resolveSession(string $token): object { return new class { public $org_id = ''; public $client_ip = ''; }; }
function logger(): \Psr\Log\LoggerInterface { return new class implements \Psr\Log\LoggerInterface { public function log($level, $message, array $context = []): void {} }; }
class Note extends \Illuminate\Database\Eloquent\Model { }