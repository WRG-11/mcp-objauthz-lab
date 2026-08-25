<?php
// Test fixture for rule: mcp-authz-scope-from-request-header-php
//
// S10 (forwarded-header-as-scope). Laravel/Symfony MCP handler receives request headers.
// A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
// for IP scoping) as the authorization scope has the same client-controlled
// input as the JS sibling. The legitimate-neighbor reads a non-scope header
// (X-Request-Id) for logging and must stay silent.
//
// Corpus signatures (2 total):
// - POOL processwire-mcp HttpMiddleware::requireAuth: $request->getHeaderLine('Authorization') → token compare / tenant pick
// - ECO PSR-7: Nyholm/psr7 MessageTrait::getHeaderLine, slimphp/Slim-Psr7 Message::getHeaderLine (framework defs, not call-sites)
//
// CONFIDENCE NOTE: Outside processwire-mcp::requireAuth, PHP-pool getHeaderLine hits are
// framework METHOD DEFINITIONS, not authz call-sites. Lower confidence than other 4 languages.
// Recommend taint (header-source → auth-sink) rather than bare presence match.
//
// Two-way canary axis: is the header read (inbound, for a decision) or written (outbound) /
// read for a non-authz concern (locale, tracing, negotiation)? (write or non-authz ⇒ SILENT)

use Illuminate\Http\Request;
use Psr\Http\Message\ServerRequestInterface;

// FIRE: getHeaderLine consumed by requireAuth / token compare / tenant pick (canonical S10)
function noteGetScopedVuln(ServerRequestInterface $request, string $token): array {
    $session = resolveSession($token);
    // ruleid: mcp-authz-scope-from-request-header-php
    $auth = $request->getHeaderLine('Authorization');
    if (!$auth) { return ['error' => 'missing authorization header']; }
    // ... token compare / tenant pick using $auth
    $headerOrg = $request->getHeaderLine('x-org-id') ?? $session->org_id;
    return Note::where('org_id', $headerOrg)->get()->toArray();
}

// FIRE: Laravel $request->header() with authz decision
function noteGetScopedLaravelVuln(Request $request, string $token): \Illuminate\Database\Eloquent\Collection {
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

// FIRE: PSR-7 $request->getHeaderLine (raw) with authz decision
function noteGetScopedPsr7Vuln(ServerRequestInterface $request, string $token): array {
    $session = resolveSession($token);
    // ruleid: mcp-authz-scope-from-request-header-php
    $headerOrg = $request->getHeaderLine('x-org-id') ?? $session->org_id;
    return Note::where('org_id', $headerOrg)->get()->toArray();
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

// SILENT: header read for content negotiation (Accept, Content-Type)
function logNegotiation(Request $request): void {
    // ok: mcp-authz-scope-from-request-header-php
    $accept = $request->header('Accept');
    $ctype = $request->header('Content-Type');
    logger()->info('negotiation', ['accept' => $accept, 'content_type' => $ctype]);
}

// SILENT: header merely logged (not used for authz)
function logHeaders(Request $request): void {
    // ok: mcp-authz-scope-from-request-header-php
    $xff = $request->header('x-forwarded-for');
    logger()->info('headers', ['xff' => $xff]);
}

function resolveSession(string $token): object { return new class { public $org_id = ''; public $client_ip = ''; }; }
function logger(): \Psr\Log\LoggerInterface { return new class implements \Psr\Log\LoggerInterface { public function log($level, $message, array $context = []): void {} }; }
class Note extends \Illuminate\Database\Eloquent\Model { }