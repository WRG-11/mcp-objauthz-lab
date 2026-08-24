// Test fixture for rule: mcp-unscoped-query-object-fetch-java
//
// The query-scoped shape: a repository fetch where the tenant key is either
// present in the filter (safe) or omitted (the S7 bug). The rule fires on the
// omission and stays silent when the tenant key is bound.

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Example;

// FIRE: findById with only id (no tenant key)
public Credential getCredentialVuln(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    return credentialRepository.findById(id).orElse(null);
}

// OK: findById with tenant key in spec
public Credential getCredentialSafe(String id, String workspaceId) {
    // ok: mcp-unscoped-query-object-fetch-java
    Credential probe = new Credential();
    probe.setId(id);
    probe.setWorkspaceId(workspaceId);
    return credentialRepository.findOne(Example.of(probe)).orElse(null);
}

// FIRE: findById with only id
public Note getNoteVuln(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    return noteRepository.findById(id).orElse(null);
}

// OK: findById with orgId in example
public Note getNoteSafe(String id, String orgId) {
    // ok: mcp-unscoped-query-object-fetch-java
    Note probe = new Note();
    probe.setId(id);
    probe.setOrgId(orgId);
    return noteRepository.findOne(Example.of(probe)).orElse(null);
}

// FIRE: deleteById with only id
public void deleteRecordVuln(String id) {
    // ruleid: mcp-unscoped-query-object-fetch-java
    noteRepository.deleteById(id);
}

// OK: delete with tenant key
public void deleteRecordSafe(String id, String projectId) {
    // ok: mcp-unscoped-query-object-fetch-java
    Note probe = new Note();
    probe.setId(id);
    probe.setProjectId(projectId);
    noteRepository.delete(noteRepository.findOne(Example.of(probe)).orElse(null));
}

interface CredentialRepository extends JpaRepository<Credential, String> {}
interface NoteRepository extends JpaRepository<Note, String> {}

CredentialRepository credentialRepository = null;
NoteRepository noteRepository = null;

class Credential {
    String id;
    String workspaceId;
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getWorkspaceId() { return workspaceId; }
    public void setWorkspaceId(String workspaceId) { this.workspaceId = workspaceId; }
}

class Note {
    String id;
    String orgId;
    String projectId;
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getOrgId() { return orgId; }
    public void setOrgId(String orgId) { this.orgId = orgId; }
    public String getProjectId() { return projectId; }
    public void setProjectId(String projectId) { this.projectId = projectId; }
}