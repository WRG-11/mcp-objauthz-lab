// Real-capture fixture for rule: mcp-ratelimit-scope-from-forwarded-header
//
// From audit: SurfSense rate_limiter.py uses X-Forwarded-For as the client
// identity key for rate limiting. This is the VULN pattern the S11 rule
// should catch — the FIRE half of the two-way canary.
//
// FIRE: X-Forwarded-For used as quota/rate-limit identity key (authz decision).

// VULN: X-Forwarded-For used as quota key (bypassable by spoofing XFF)
async function createNoteWithQuotaVuln({ token, title, body }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const quotaKey = extra?.requestInfo?.headers?.["x-forwarded-for"] ?? session.userId;
  const count = store.getQuotaCount(quotaKey);
  if (count >= 10) throw new Error("Quota exceeded");
  store.incrementQuota(quotaKey);
  return store.createNote({ orgId: session.orgId, ownerId: session.userId, title, body });
}

// VULN: X-Forwarded-For used as quota key WITHOUT optional chaining (for rule testing)
async function createNoteWithQuotaVulnNoOptChain({ token, title, body }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const quotaKey = extra.requestInfo.headers["x-forwarded-for"] ?? session.userId;
  const count = store.getQuotaCount(quotaKey);
  if (count >= 10) throw new Error("Quota exceeded");
  store.incrementQuota(quotaKey);
  return store.createNote({ orgId: session.orgId, ownerId: session.userId, title, body });
}

// VULN: X-Real-IP used as rate-limit key (same pattern)
async function apiCallWithRateLimitVuln({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const rateLimitKey = extra?.requestInfo?.headers?.["x-real-ip"] ?? session.userId;
  if (store.isRateLimited(rateLimitKey)) throw new Error("Rate limited");
  return store.makeApiCall(session.userId);
}

// VULN: X-Client-IP used as quota key (same pattern)
async function createResourceWithQuotaVuln({ token, name }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const quotaKey = extra?.requestInfo?.headers?.["x-client-ip"] ?? session.userId;
  if (store.getQuotaCount(quotaKey) >= 5) throw new Error("Quota exceeded");
  store.incrementQuota(quotaKey);
  return store.createResource({ ownerId: session.userId, name });
}

// OK: quota keyed on session (server-trusted), XFF ignored
async function createNoteWithQuotaFixed({ token, title, body }, extra) {
  const session = resolveSession(store, token);
  // ok: mcp-ratelimit-scope-from-forwarded-header
  const quotaKey = session.userId; // session-derived, not header
  const count = store.getQuotaCount(quotaKey);
  if (count >= 10) throw new Error("Quota exceeded");
  store.incrementQuota(quotaKey);
  return store.createNote({ orgId: session.orgId, ownerId: session.userId, title, body });
}

// OK: X-Forwarded-For read for logging only, not used for quota
async function logRequestWithXff(_args, extra) {
  // ok: mcp-ratelimit-scope-from-forwarded-header
  const clientIp = extra?.requestInfo?.headers?.["x-forwarded-for"];
  logger.info({ clientIp, event: "tool_call" });
}

// The cases below cover every statement shape and header-read spelling the
// rule lists; removing any one of them from the rule fails this fixture.

// VULN: `??` fallback, the key only reaches a call statement.
async function bumpQuotaCallOnly({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const key = extra?.requestInfo?.headers?.get("x-forwarded-for") ?? session.userId;
  store.incrementQuota(key);
}

// VULN: `??` fallback, the key only reaches a declaration's initializer.
async function readQuotaDeclOnly({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const key = extra?.requestInfo?.headers.get("x-forwarded-for") ?? session.userId;
  const used = store.getQuotaCount(key);
  return used;
}

// VULN: `||` fallback, call statement.
async function bumpQuotaOr({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const key = extra.requestInfo.headers?.get("x-real-ip") || session.userId;
  store.incrementQuota(key);
}

// VULN: `||` fallback, `if` condition.
async function checkThrottleOr({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const key = extra.requestInfo.headers.get("x-client-ip") || session.userId;
  if (store.isThrottled(key)) throw new Error("Rate limited");
}

// VULN: `||` fallback, declaration's initializer.
async function readQuotaOr({ token }, extra) {
  const session = resolveSession(store, token);
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  const key = extra.requestInfo.headers["x-forwarded-for"] || session.userId;
  const used = store.getQuotaCount(key);
  return used;
}

// VULN: the header value is an object property of the counter call.
async function bumpQuotaObject(_args, extra) {
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  store.incrementQuota({ client: extra.requestInfo.headers["x-real-ip"] });
}

// VULN: the header value is a positional argument of the counter call.
async function bumpQuotaPositional(_args, extra) {
  // ruleid: mcp-ratelimit-scope-from-forwarded-header
  store.incrementQuota(extra.requestInfo.headers["x-client-ip"]);
}

// OK: a request-id header keys the counter. It is not a client identity.
// Pins the header-name filter.
async function bumpQuotaByRequestId({ token }, extra) {
  const session = resolveSession(store, token);
  // ok: mcp-ratelimit-scope-from-forwarded-header
  const key = extra.requestInfo.headers["x-request-id"] ?? session.userId;
  store.incrementQuota(key);
}

// OK: the forwarded address is stored for analytics, not as a quota key.
// Pins the counter-name filter.
async function recordVisit({ token }, extra) {
  const session = resolveSession(store, token);
  // ok: mcp-ratelimit-scope-from-forwarded-header
  const ip = extra.requestInfo.headers["x-forwarded-for"] ?? session.userId;
  store.recordVisit(ip);
}
