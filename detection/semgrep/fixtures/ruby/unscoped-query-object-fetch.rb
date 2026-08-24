# Test fixture for rule: mcp-unscoped-query-object-fetch-ruby
#
# The query-scoped shape: an ActiveRecord fetch where the tenant key is either
# present in the query (safe) or omitted (the S7 bug). The rule fires on the
# omission and stays silent when the tenant key is bound.

# FIRE: find by id only (no tenant key)
def get_credential_vuln(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Credential.find(id)
end

# OK: find by id with tenant key
def get_credential_safe(id, workspace_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Credential.find_by(id: id, workspace_id: workspace_id)
end

# FIRE: find_by with only id
def get_note_vuln(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.find_by(id: id)
end

# OK: find_by with org_id
def get_note_safe(id, org_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Note.find_by(id: id, org_id: org_id)
end

# FIRE: delete with only id
def delete_record_vuln(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.delete(id)
end

# OK: delete with project_id
def delete_record_safe(id, project_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Note.find_by(id: id, project_id: project_id)&.destroy
end

class Credential < ActiveRecord::Base; end
class Note < ActiveRecord::Base; end