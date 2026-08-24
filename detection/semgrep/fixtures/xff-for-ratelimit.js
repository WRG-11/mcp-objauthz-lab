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