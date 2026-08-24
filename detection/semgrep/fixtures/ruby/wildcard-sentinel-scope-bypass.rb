# Test fixture for rule: mcp-wildcard-sentinel-scope-bypass-ruby
#
# S4 (wildcard/sentinel bypass). A magic "all" or "*" sentinel on a scope
# parameter is honored in an AUTHORIZATION CONTEXT (it controls whether to
# widen scope and return all tenants' data) without a role check.
# A textual "*" or "all" comparison in markup rendering, UI filters, or
# logging is NOT an authz decision and must stay silent.
#
# TWO-WAY CANARY:
# - FIRE: wildcard in authz bypass context (gates scope widening, returns all orgs' data)
# - SILENT: wildcard in non-authz context (markup, UI filter, logging)

# FIRE: wildcard comparison gates returning all orgs' data (authz bypass)
def vuln_export(token, org_id)
  session = resolve_session(token)
  # ruleid: mcp-wildcard-sentinel-scope-bypass-ruby
  if org_id == "*" || org_id == "all"
    Note.all
  else
    Note.where(org_id: session.org_id)
  end
end

# FIRE: ternary with wildcard selecting all-orgs vs scoped data (authz bypass)
def vuln_export_ternary(token, org_id)
  session = resolve_session(token)
  # ruleid: mcp-wildcard-sentinel-scope-bypass-ruby
  org_id == "*" ? Note.all : Note.where(org_id: session.org_id)
end

# FIRE: wildcard check skips normal org scoping (authz bypass)
def vuln_export_skip_scope(token, org_id)
  session = resolve_session(token)
  # ruleid: mcp-wildcard-sentinel-scope-bypass-ruby
  if org_id == "*"
    Note.all
  end
  # no org scoping in this branch -- wildcard bypassed it
  Note.all
end

# OK: wildcard guarded by admin role check
def fixed_export_guarded(token, org_id)
  session = resolve_session(token)
  require_admin_role(session)
  # ok: mcp-wildcard-sentinel-scope-bypass-ruby
  if org_id == "*" || org_id == "all"
    Note.all
  else
    Note.where(org_id: session.org_id)
  end
end

# SILENT: wildcard in markup rendering (textual, not authz)
# The parameter name matches scope regex but context is markup, not authz
def render_markdown(text)
  # ok: mcp-wildcard-sentinel-scope-bypass-ruby
  text.gsub(/\*(.+?)\*/, '<b>\1</b>')
end

# SILENT: wildcard in UI search filter (textual comparison, not authz)
# The variable name matches scope regex but it's a UI filter value, not scope
def filter_notes_by_scope(notes, scope)
  # ok: mcp-wildcard-sentinel-scope-bypass-ruby
  if scope == "all"
    notes # UI "show all" filter, not authz bypass
  else
    notes.select { |n| n.scope == scope }
  end
end

# SILENT: wildcard in logging (textual, not authz)
def log_scope_value(scope)
  # ok: mcp-wildcard-sentinel-scope-bypass-ruby
  logger.info("wildcard scope requested") if scope == "*"
end

def resolve_session(token); end
def require_admin_role(session); end
def logger; end
class Note
  def self.all; end
  def self.where(conditions); end
  attr_accessor :scope
end