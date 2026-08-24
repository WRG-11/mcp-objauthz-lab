# Test fixture for rule: mcp-authz-scope-from-request-header-ruby
#
# S10 (forwarded-header-as-scope). Rails/Sinatra MCP handler receives request headers.
# A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
# for IP scoping) as the authorization scope has the same client-controlled
# input as the JS sibling. The legitimate-neighbor reads a non-scope header
# (X-Request-Id) for logging and must stay silent.
#
# TWO-WAY CANARY:
# - FIRE: header value feeds an authz decision (scope/org-id selection, Note.where(org_id: headerValue))
# - SILENT: header read ONLY for logging (no authz decision)

# FIRE: header value used to select org scope in a model scope (authz decision)
def note_get_scoped_vuln(token)
  session = resolve_session(token)
  # ruleid: mcp-authz-scope-from-request-header-ruby
  header_org = request.headers["x-org-id"] || session.org_id
  Note.where(org_id: header_org)
end

# FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
def note_get_scoped_by_ip_vuln(token)
  session = resolve_session(token)
  # ruleid: mcp-authz-scope-from-request-header-ruby
  fwd = request.headers["x-forwarded-for"] || session.client_ip
  Note.where(client_ip: fwd)
end

# FIRE: header used directly as org_id in a query filter (authz decision)
def note_get_by_query_vuln(token, id)
  session = resolve_session(token)
  # ruleid: mcp-authz-scope-from-request-header-ruby
  header_org = request.headers["x-org-id"] || session.org_id
  Note.find_by(id: id, org_id: header_org)
end

# OK: scope comes from the session; no header is consulted at all.
def note_get_scoped_fixed(token)
  session = resolve_session(token)
  # ok: mcp-authz-scope-from-request-header-ruby
  Note.where(org_id: session.org_id)
end

# OK (legitimate neighbor): a non-scope header read for logging only.
def log_request
  # ok: mcp-authz-scope-from-request-header-ruby
  req_id = request.headers["x-request-id"]
  logger.info("tool invoked, req_id=#{req_id}")
end

# SILENT: scope-shaped header (X-Forwarded-For) read ONLY for logging, no authz decision.
# This is the two-way canary: reading XFF for logging must NOT fire.
def log_client_ip
  # ok: mcp-authz-scope-from-request-header-ruby
  client_ip = request.headers["x-forwarded-for"]
  logger.info("rate-limit check, client_ip=#{client_ip}")
end

# SILENT: scope-shaped header read into a variable but NEVER used for authz
def read_header_but_dont_use(token)
  session = resolve_session(token)
  # ok: mcp-authz-scope-from-request-header-ruby
  _unused = request.headers["x-org-id"]
  Note.where(org_id: session.org_id)
end

def resolve_session(token); end
def request; end
def logger; end
class Note
  def self.where(conditions); end
  def self.find_by(conditions); end
end