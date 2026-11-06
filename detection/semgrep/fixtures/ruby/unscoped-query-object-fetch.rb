# Test fixture for rule: mcp-unscoped-query-object-fetch-ruby
#
# The query-scoped shape: an ActiveRecord fetch where the tenant key is either
# present in the query (safe) or omitted (the S7 bug). The rule fires on the
# omission and stays silent when the tenant key is bound.
#
# Corpus signatures (5 FIRE + 4 SILENT ideal canary from miru-web):
# FIRE (unscoped, receiver is bare Model constant):
# - woofed-crm: Deal.find(params[:id]), User.find(params[:id])
# - sepomex: City.find(params[:id])
# - miru-web: Company.find_by(id: params[:id]) (with skip_after_action :verify_authorized)
# SILENT (scoped through owner/tenant association):
# - miru-web: current_company.leaves.find(params[:id])
# - miru-web: current_user.companies.find(params[:id])
# - miru-web: Employment.find_by!(user_id: params[:id], company_id: current_company.id)
# - miru-web: current_company.projects.kept.includes(...).find(params[:id])
#
# Two-way canary axis: is the receiver a class constant (FIRE) or an owner/tenant scope chain (SILENT)?

# FIRE: receiver is a CLASS CONSTANT — Deal.find(params[:id]), Company.find_by(id: params[:id])
def get_credential_vuln(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Credential.find(id)
end

# FIRE: find_by with only id
def get_note_vuln(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.find_by(id: id)
end

# FIRE: find_by! with only id
def get_note_vuln_bang(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.find_by!(id: id)
end

# FIRE: where(id: id).first
def get_note_vuln_where(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.where(id: id).first
end

# FIRE: delete with only id
def delete_record_vuln(id)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.delete(id)
end

# OK: tenant key in criteria — Model::findOneBy(['id'=>$id,'tenant'=>$t])
def get_credential_safe(id, workspace_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Credential.find_by(id: id, workspace_id: workspace_id)
end

# OK: find_by with org_id
def get_note_safe(id, org_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Note.find_by(id: id, org_id: org_id)
end

# OK: delete with project_id
def delete_record_safe(id, project_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Note.find_by(id: id, project_id: project_id)&.destroy
end

# SILENT: receiver is an OWNER/TENANT SCOPE CHAIN — current_company.leaves.find(...)
def get_leave_safe(id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  current_company.leaves.find(id)
end

# SILENT: current_user.companies.find(...)
def get_company_safe(id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  current_user.companies.find(id)
end

# SILENT: find_by! with tenant column in args — Employment.find_by!(user_id: ..., company_id: current_company.id)
def get_employment_safe(user_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Employment.find_by!(user_id: user_id, company_id: current_company.id)
end

# SILENT: current_company.projects.kept.includes(...).find(...)
def get_project_safe(id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  current_company.projects.kept.includes(:tasks).find(id)
end

# FIRE: a Rails action, id from params.
def show
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.find(params[:id])
end

# FIRE: the other fetch shapes with an id from params (miru-web:
# Company.find_by(id: params[:id])).
def edit
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Company.find_by(id: params[:id])
end

def update
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.find_by!(id: params[:note_id])
end

def preview
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.where(id: params[:id]).first
end

def destroy
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.delete(params[:id])
end

# FIRE: an MCP tool with a keyword argument.
def call(note_id:)
  # ruleid: mcp-unscoped-query-object-fetch-ruby
  Note.find(note_id)
end

# OK: the id comes from the signed-in user, not from the caller. Pins the
# parameter-origin requirement.
def pinned_note(format)
  pinned = current_user.pinned_note_id
  # ok: mcp-unscoped-query-object-fetch-ruby
  Note.find(pinned)
end

# OK: a where-scope chain is not a bare model constant. Pins the $MODEL filter.
def get_note_in_org(id, org_id)
  # ok: mcp-unscoped-query-object-fetch-ruby
  Note.where(org_id: org_id).find(id)
end

# OK: a background job; the id was enqueued by server code. Pins the
# perform exclusion.
class NoteExportJob < ApplicationJob
  def perform(note_id)
    # ok: mcp-unscoped-query-object-fetch-ruby
    Note.find(note_id)
  end
end

# OK: a filesystem call, not a record lookup. Pins the File/Dir exclusion.
def remove_export(path)
  # ok: mcp-unscoped-query-object-fetch-ruby
  File.delete(path)
end

class Credential < ActiveRecord::Base; end
class Note < ActiveRecord::Base; end
class Employment < ActiveRecord::Base; end

def current_company; Company.new; end
def current_user; User.new; end
class Company < ActiveRecord::Base; end
class User < ActiveRecord::Base; end