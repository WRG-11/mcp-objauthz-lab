// Test fixture for rule: mcp-unscoped-query-object-fetch-java
//
// The query-scoped shape: a repository fetch where the tenant key is either
// present in the filter (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.
//
// Corpus signatures (5 total):
// - 4 POOL (eugenp/tutorials: Spring-5 JPA, Hilla, Groovy-Spock mocks)
// - 1 ECO (axelor/axelor-open-platform: JPA.getReferenceById)
//
// Two-way canary axis: is the fetch narrowed by an owner/tenant? (present ⇒ SILENT)

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Example;

// FIRE: findById with only id (no tenant key) — Spring-Data JPA standard
public Credential getCredentialVuln(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    return credentialRepository.findById(id).orElse(null);
}

// FIRE: getReferenceById with only id
public Credential getCredentialByRef(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    return credentialRepository.getReferenceById(id);
}

// FIRE: getById with only id
public Note getNoteById(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    return noteRepository.getById(id);
}

// FIRE: deleteById with only id
public void deleteRecordVuln(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    noteRepository.deleteById(id);
}

// FIRE: findOneById with only id
public Note getNoteByOneId(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    return noteRepository.findOneById(id).orElse(null);
}

// OK: findById with tenant key in Example (SILENT - owner/tenant scoped)
public Credential getCredentialSafe(String id, String workspaceId) {
    // ok: mcp-unscoped-query-object-fetch-java
    Credential probe = new Credential();
    probe.setId(id);
    probe.setWorkspaceId(workspaceId);
    return credentialRepository.findOne(Example.of(probe)).orElse(null);
}

// OK: findById with orgId in example
public Note getNoteSafe(String id, String orgId) {
    // ok: mcp-unscoped-query-object-fetch-java
    Note probe = new Note();
    probe.setId(id);
    probe.setOrgId(orgId);
    return noteRepository.findOne(Example.of(probe)).orElse(null);
}

// OK: delete with tenant key
public void deleteRecordSafe(String id, String projectId) {
    // ok: mcp-unscoped-query-object-fetch-java
    Note probe = new Note();
    probe.setId(id);
    probe.setProjectId(projectId);
    noteRepository.delete(noteRepository.findOne(Example.of(probe)).orElse(null));
}

// SILENT: derived finder with tenant column — findByIdAndCompanyId(id, currentCompanyId)
public Note getNoteDerived(String id, String companyId) {
    // ok: mcp-unscoped-query-object-fetch-java
    return noteRepository.findByIdAndCompanyId(id, companyId).orElse(null);
}

// SILENT: @Query with tenant filter
public Note getNoteQuery(String id, String tenantId) {
    // ok: mcp-unscoped-query-object-fetch-java
    return noteRepository.findByIdAndTenantId(id, tenantId);
}

interface CredentialRepository extends JpaRepository<Credential, String> {
    Credential findByIdAndCompanyId(String id, String companyId);
    Credential findByIdAndTenantId(String id, String tenantId);
}
interface NoteRepository extends JpaRepository<Note, String> {
    Note findByIdAndCompanyId(String id, String companyId);
    Note findByIdAndTenantId(String id, String tenantId);
}

CredentialRepository credentialRepository = null;
NoteRepository noteRepository = null;

class Credential {
    String id;
    String workspaceId;
    String companyId;
    String tenantId;
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getWorkspaceId() { return workspaceId; }
    public void setWorkspaceId(String workspaceId) { this.workspaceId = workspaceId; }
    public String getCompanyId() { return companyId; }
    public void setCompanyId(String companyId) { this.companyId = companyId; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }
}

class Note {
    String id;
    String orgId;
    String projectId;
    String companyId;
    String tenantId;
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getOrgId() { return orgId; }
    public void setOrgId(String orgId) { this.orgId = orgId; }
    public String getProjectId() { return projectId; }
    public void setProjectId(String projectId) { this.projectId = projectId; }
    public String getCompanyId() { return companyId; }
    public void setCompanyId(String companyId) { this.companyId = companyId; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String tenantId) { this.tenantId = tenantId; }
}