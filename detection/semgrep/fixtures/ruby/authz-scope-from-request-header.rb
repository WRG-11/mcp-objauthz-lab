# Test fixture for rule: mcp-authz-scope-from-request-header-ruby
#
# S10 (forwarded-header-as-scope). Rails/Sinatra MCP handler receives request headers.
# A handler that trusts a tenant/identity header (X-Org-Id, or X-Forwarded-For
# for IP scoping) as the authorization scope has the same client-controlled
# input as the JS sibling. The legitimate-neighbor reads a non-scope header
# (X-Request-Id) for logging and must stay silent.
#
# Corpus signatures (5 total, all POOL):
# - miru-web/authenticable: request.headers["X-Auth-Email"].presence; request.headers["X-Auth-Token"] → auth
# - miru-web/mcp_controller.rb: authorization: request.headers["Authorization"]; origin = request.headers["Origin"] → validate_origin_header!
# - miru-web/agent/base_controller: request.headers["Authorization"].to_s.delete_prefix("Bearer ") → auth
# - woofed-crm/internal_controller: request.headers['Authorization'] → authenticate_user
# - miru-web/application_controller: request.headers["X-Miru-Locale"] / request.headers["Accept-Language"] (SILENT: locale)
# - miru-web/oauth_client: request.headers["Authorization"] = "Basic #{...}" (SILENT: outbound Faraday write)
#
# Two-way canary axis: is the header read (inbound, for a decision) or written (outbound) /
# read for a non-authz concern (locale, tracing, negotiation)? (write or non-authz ⇒ SILENT)

# The rule is a taint rule, so a finding sits on the SINK: the value that
# selects the scope in a query. `ruleid:` markers are above that query.

# FIRE: header value used to select org scope in a model scope (authz decision)
def note_get_scoped_vuln(token)
  session = resolve_session(token)
  header_org = request.headers["x-org-id"] || session.org_id
  # ruleid: mcp-authz-scope-from-request-header-ruby
  Note.where(org_id: header_org)
end

# FIRE: request.headers.fetch with authz decision
def note_get_scoped_fetch_vuln(token)
  session = resolve_session(token)
  header_org = request.headers.fetch("x-org-id", session.org_id)
  # ruleid: mcp-authz-scope-from-request-header-ruby
  Note.where(org_id: header_org)
end

# FIRE (IP-scoping variant): X-Forwarded-For used to select client IP scope
def note_get_scoped_by_ip_vuln(token)
  session = resolve_session(token)
  fwd = request.headers["x-forwarded-for"] || session.client_ip
  # ruleid: mcp-authz-scope-from-request-header-ruby
  Note.where(client_ip: fwd)
end

# FIRE: header used directly as org_id in a query filter (authz decision)
def note_get_by_query_vuln(token, id)
  session = resolve_session(token)
  header_org = request.headers["x-org-id"] || session.org_id
  # ruleid: mcp-authz-scope-from-request-header-ruby
  Note.find_by(id: id, org_id: header_org)
end

# OK: a bearer token from the Authorization header, checked by the server, is
# authentication, not a client-chosen scope. (This case was marked `ruleid`
# before, which contradicted the rule's own header list.)
def authenticate_with_bearer(token)
  session = resolve_session(token)
  # ok: mcp-authz-scope-from-request-header-ruby
  auth_header = request.headers["Authorization"]
  user = User.authenticate_with_token(auth_header)
  user
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

# SILENT: header read for locale/negotiation (X-Miru-Locale, Accept-Language)
def log_locale
  # ok: mcp-authz-scope-from-request-header-ruby
  locale = request.headers["X-Miru-Locale"]
  logger.info("locale=#{locale}")
end

# SILENT: outbound Faraday WRITE — request.headers["Authorization"] = "Basic #{...}"
def outbound_write
  # ok: mcp-authz-scope-from-request-header-ruby
  request.headers["Authorization"] = "Basic #{Base64.encode64('user:pass')}"
  Faraday.post("https://api.example.com", nil, request.headers)
end

# FIRE: Rack env spelling, rocket-style hash key.
def project_list_env_vuln
  tenant = request.env["HTTP_X_TENANT_ID"]
  # ruleid: mcp-authz-scope-from-request-header-ruby
  Project.where(:tenant_id => tenant)
end

# FIRE: finder by primary key taken from the header.
def account_show_vuln
  # ruleid: mcp-authz-scope-from-request-header-ruby
  Account.find(request.headers["x-account-id"])
end

# OK (legitimate neighbor): a correlation header as a finder key is not a
# scope header. Pins the header-name regex.
def audit_show
  # ok: mcp-authz-scope-from-request-header-ruby
  AuditEvent.find(request.headers["x-request-id"])
end

# OK: a non-scope Rack env entry. Pins the env-name regex.
def audit_show_env
  # ok: mcp-authz-scope-from-request-header-ruby
  AuditEvent.find(request.env["HTTP_X_REQUEST_ID"])
end

# OK: the header narrows a non-scope column inside the session's org. Pins the
# scope-key regex.
def list_events_from_ip(token)
  session = resolve_session(token)
  client_ip = request.headers["x-forwarded-for"]
  # ok: mcp-authz-scope-from-request-header-ruby
  Event.where(org_id: session.org_id, source_ip: client_ip)
end

# OK: the header value is written with a scope-named key, not used to choose
# whose rows are read. Pins the query-method regex.
def record_access
  # ok: mcp-authz-scope-from-request-header-ruby
  AccessLog.create(client_ip: request.headers["x-forwarded-for"])
end

def resolve_session(token); end
def request; end
def logger; end
def current_company; Company.new; end
class Note
  def self.where(conditions); end
  def self.find_by(conditions); end
end
class User
  def self.authenticate_with_token(token); end
end
class Company < ActiveRecord::Base; end
class User < ActiveRecord::Base; end