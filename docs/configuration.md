# Environment variables

Each scenario is controlled by an independent env var (all default to `"vuln"`):

| Var | Controls | Vuln behaviour | Fixed behaviour |
|---|---|---|---|
| `LAB_MODE` / `LAB_S1` | S1 — `note_delete` | Cross-tenant delete succeeds | `requireOrgAccess()` blocks it |
| `LAB_S2` | S2 — `note_search` | `org_id` param overrides session scope | `org_id` ignored; session scope always used |
| `LAB_S3` | S3 — `note_batch_get` | All resolved notes returned regardless of org | Notes filtered to `session.orgId` |
| `LAB_S4` | S4 — `note_export` | `org_id="*"/"all"` dumps all tenants | `org_id` ignored; own org only |
| `LAB_S5` | S5 — `note_admin_get` | No role check; any token reaches cross-org lookup | `requireAdminRole()` blocks non-admins |
| `LAB_S6` | S6 — `note_create_in_org` | `org_id` param trusted as write target | `org_id` ignored; note created in session's own org |
| `LAB_S7` | S7 — `note_get_by_query` | tenant key omitted from the query filter; any org's id resolves | `orgId` bound into the same filter |
| `LAB_S8` | S8 — `note://` resource | `orgId` URI path segment trusted as scope | URI segment ignored; session's own org used |
| `LAB_S9` | S9 — `note_share_redeem` | decoded grant's `noteId` trusted with no session re-check | `requireOrgAccess()` re-checked against the resolved note |
| `LAB_S10` | S10 — `note_get_scoped` | `X-Org-Id` header trusted as scope (HTTP) | Header ignored; session scope always used |
| `LAB_S11` | S11 — `note_create_limited` | `X-Forwarded-For` header as quota key (HTTP) | Quota keyed to session; header ignored |
| `LAB_S12` | S12 — `note_batch_resolve` | Batch returns all resolved notes regardless of org | Each resolved note filtered to `session.orgId` |
| `LAB_S13` | S13 — `note_get_by_token_scope` | Token's scope/aud claim trusted as scope | Scope claim ignored; session scope always used |

Run all scenarios in their fixed state:

```bash
# Linux / macOS
LAB_S1=fixed LAB_S2=fixed LAB_S3=fixed LAB_S4=fixed LAB_S5=fixed LAB_S6=fixed LAB_S7=fixed LAB_S8=fixed LAB_S9=fixed LAB_S10=fixed LAB_S11=fixed LAB_S12=fixed LAB_S13=fixed npm start

# Windows PowerShell
$env:LAB_S1='fixed'; $env:LAB_S2='fixed'; $env:LAB_S3='fixed'; $env:LAB_S4='fixed'; $env:LAB_S5='fixed'; $env:LAB_S6='fixed'; $env:LAB_S7='fixed'; $env:LAB_S8='fixed'; $env:LAB_S9='fixed'; $env:LAB_S10='fixed'; $env:LAB_S11='fixed'; $env:LAB_S12='fixed'; $env:LAB_S13='fixed'; npm start
```

Isolate one scenario (e.g. test only S2):

```bash
LAB_S2=vuln LAB_S1=fixed LAB_S3=fixed LAB_S4=fixed LAB_S5=fixed LAB_S6=fixed LAB_S7=fixed LAB_S8=fixed LAB_S9=fixed LAB_S10=fixed LAB_S11=fixed LAB_S12=fixed LAB_S13=fixed npm start
```
