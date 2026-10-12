# MCP Object-Authz Lab

[![lab-integrity](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/WRG-11/mcp-objauthz-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A vulnerable-by-design [MCP](https://modelcontextprotocol.io) server for practising
object-level authorization bugs (BOLA / IDOR, [CWE-639](https://cwe.mitre.org/data/definitions/639.html),
[CWE-862](https://cwe.mitre.org/data/definitions/862.html)) in MCP tools. Thirteen hands-on
scenarios, each one a different variant of the bug, each with a vulnerable build and a
fixed build.

```bash
git clone https://github.com/WRG-11/mcp-objauthz-lab && cd mcp-objauthz-lab
npm install && npm run poc    # Node.js 20 or newer
```

The PoC is an MCP client. It starts the server on your machine and sends the same
cross-tenant request to both builds. Two rows of its 38-row output:

```
  SC   BUILD  ACTION                                         OUTCOME   EXPECT    OK
  S2   vuln   note_search  scope-as-param (Alice→org_globex) LEAKED    LEAKED    ✓
  S2   fixed  note_search  scope-as-param (Alice→org_globex) SCOPED    SCOPED    ✓

  Two-way gate: PASS (38/38 rows OK)
```

Same caller, same request: the vulnerable build returns another tenant's notes, the fixed
build scopes the result to the caller's own tenant.

[Try the scenarios without the answers](#try-the-challenges) · [Walkthroughs](docs/scenarios.md) · [Hunt checklist](docs/hunt-checklist.md)

## Why this lab exists

Most MCP security attention goes to prompt injection and tool poisoning.
Object-level authorization is a different class, and the usual prompt-injection
test suites and scanners do not find it. When an MCP server is multi-tenant, every
tool that resolves an object from a client-supplied id must verify the caller is
allowed to touch that object. Miss the check on a single tool and a caller in one
tenant can read or change another tenant's objects.

This is not theoretical. Asana's MCP connector (Jun 2025) leaked data across tenant
boundaries for roughly 1,000 customer organizations
([Pomerium's writeup](https://www.pomerium.com/blog/asanas-ai-connector-leak-exposed-sensitive-data-across-organizations-what-it-means-for-mcp-security)).
In n8n-mcp,
[CVE-2026-54052](https://www.manifold.security/blog/n8n-mcp-idor-cross-tenant-credential-theft)
let any caller read or delete another tenant's stored API keys: sequential integer
ids on a table with no tenant-id column. Both are S1/S3-shaped bugs, in production
instead of a lab.

## Try the challenges

The scenarios are in [`challenges/`](challenges/README.md), with no hints until you
open [`solutions/`](solutions/). Each runs locally in under 5 minutes.

| Scenario | Pattern |
|---|---|
| [S1](challenges/s1.md) | Inconsistent authorization: find the single outlier |
| [S2](challenges/s2.md) | Client-supplied scope trusted as authorization |
| [S3](challenges/s3.md) | List→get asymmetry: batch skips per-object check |
| [S4](challenges/s4.md) | Wildcard/sentinel value bypasses scope filter |
| [S5](challenges/s5.md) | Role/token-type bypass: admin-named tool, no role check |
| [S6](challenges/s6.md) | Foreign-parent injection: create trusts a caller-supplied org |
| [S7](challenges/s7.md) | Unscoped query: tenant key omitted from the filter (the real-world shape) |
| [S8](challenges/s8.md) | Resource-URI-as-scope: the resources/read surface, not tools/call |
| [S9](challenges/s9.md) | Authz-from-client-round-tripped-value: an editable share grant |
| [S10](challenges/s10.md) | Forwarded-header-as-scope: a trusted request header (HTTP transport) |
| [S11](challenges/s11.md) | X-Forwarded-For quota bypass: a trusted request header for rate limiting (HTTP transport) |
| [S12](challenges/s12.md) | Batch/bulk endpoint BOLA: multi-object endpoint without per-item tenant filter |
| [S13](challenges/s13.md) | JWT/token scope confusion: token's scope/aud claim vs actual permissions mismatch |

Walkthroughs with hints and answers are in [`docs/scenarios.md`](docs/scenarios.md).

## Quickstart (< 5 minutes)

Requirements: Node.js 20 or later.

```bash
npm install
npm test    # 74 tests: unit, docs-consistency, CI-hardening and PoC-output checks
npm run poc # 38-row two-way gate: the tools/resources wired end-to-end over MCP
npm run poc -- --json-output poc-chain-evidence.json --sarif-output poc-chain-evidence.sarif
```

Expected `npm run poc` output (38/38 rows, all scenarios + the hardened build):

```
MCP object-level authorization lab — two-way gate (13 scenarios + hardened build)

  SC   BUILD  ACTION                                         OUTCOME   EXPECT    OK
  S1   vuln   note_get    cross-tenant (Bob→Acme)            DENIED    DENIED    ✓
  S1   vuln   note_delete cross-tenant (Bob→Acme)            DELETED   DELETED   ✓
  S1   fixed  note_delete cross-tenant (Bob→Acme)            DENIED    DENIED    ✓
  S1   fixed  note_delete same-tenant  (Bob→Globex)          DELETED   DELETED   ✓
  S2   vuln   note_search  scope-as-param (Alice→org_globex) LEAKED    LEAKED    ✓
  S2   fixed  note_search  scope-as-param (Alice→org_globex) SCOPED    SCOPED    ✓
  S3   vuln   note_batch_get list→get asymm (Alice+Globex)   LEAKED    LEAKED    ✓
  S3   fixed  note_batch_get list→get asymm (Alice+Globex)   SCOPED    SCOPED    ✓
  S4   vuln   note_export  wildcard org_id='*' (Alice)       LEAKED    LEAKED    ✓
  S4   fixed  note_export  wildcard org_id='*' (Alice)       SCOPED    SCOPED    ✓
  S5   vuln   note_admin_get cross-org as Bob (user)         LEAKED    LEAKED    ✓
  S5   fixed  note_admin_get cross-org as Bob (user)         DENIED    DENIED    ✓
  S5   fixed  note_admin_get cross-org as Dana (real admin)  ALLOWED   ALLOWED   ✓
  S6   vuln   note_create_in_org org_id=org_globex (Alice)   INJECTED  INJECTED  ✓
  S6   fixed  note_create_in_org org_id=org_globex (Alice)   SCOPED    SCOPED    ✓
  S7   vuln   note_get_by_query cross-tenant (Alice→Globex)  LEAKED    LEAKED    ✓
  S7   fixed  note_get_by_query cross-tenant (Alice→Globex)  DENIED    DENIED    ✓
  S8   vuln   resources/read cross-tenant (Alice→Globex)     LEAKED    LEAKED    ✓
  S8   fixed  resources/read cross-tenant (Alice→Globex)     DENIED    DENIED    ✓
  S9   vuln   note_share_redeem tampered grant (Alice→Globex) LEAKED    LEAKED    ✓
  S9   fixed  note_share_redeem tampered grant (Alice→Globex) DENIED    DENIED    ✓
  S9   fixed  note_share_redeem own grant     (Alice→Acme)   ALLOWED   ALLOWED   ✓
  S10  vuln   note_get_scoped X-Org-Id=org_globex (Alice over HTTP) LEAKED    LEAKED    ✓
  S10  fixed  note_get_scoped X-Org-Id=org_globex (Alice over HTTP) SCOPED    SCOPED    ✓
  S11  vuln   note_create_limited quota exhausted (same XFF) BLOCKED   BLOCKED   ✓
  S11  vuln   note_create_limited quota key is 1.2.3.4       MATCH     MATCH     ✓
  S11  vuln   note_create_limited fresh server XFF=5.6.7.8 (quota key logic) CREATED   CREATED   ✓
  S11  vuln   note_create_limited quota exhausted XFF=5.6.7.8 BLOCKED   BLOCKED   ✓
  S11  fixed  note_create_limited quota exhausted (same XFF) BLOCKED   BLOCKED   ✓
  S11  fixed  note_create_limited quota key is u_alice       MATCH     MATCH     ✓
  S11  fixed  note_create_limited fresh server XFF=5.6.7.8 (quota key logic) CREATED   CREATED   ✓
  S11  fixed  note_create_limited quota exhausted XFF=5.6.7.8 BLOCKED   BLOCKED   ✓
  S12  vuln   note_batch_resolve batch with Globex id (Alice) LEAKED    LEAKED    ✓
  S12  fixed  note_batch_resolve batch with Globex id (Alice) SCOPED    SCOPED    ✓
  S13  vuln   note_get_by_token_scope scope=org_globex (Alice) LEAKED    LEAKED    ✓
  S13  fixed  note_get_by_token_scope scope=org_globex (Alice) SCOPED    SCOPED    ✓
  ALL  fixed  13 cross-tenant routes (Bob→Acme)              BLOCKED   BLOCKED   ✓
  ALL  fixed  legitimate access (Dana admin + Bob own note)  ALLOWED   ALLOWED   ✓

  Two-way gate: PASS (38/38 rows OK)
```

The PoC is a real MCP client. It spawns the server over stdio, locally, with no
network and no third party, and runs a two-way gate per scenario: in the `vuln`
build the exploit succeeds; in the `fixed` build it is blocked and legitimate
same-org access still works (no false positive).

`--json-output` writes the structured evidence contract used by the optional
toolkit adapter. `--sarif-output` writes only observed vulnerability outcomes
from the intentionally vulnerable build; fixed controls and expected denials
are not emitted as findings.

The final `ALL` rows apply that same two-way discipline to the whole server at
once. With every scenario `fixed`, each cross-tenant route is closed while legitimate
access (an admin's cross-org read, a user's own note) still works. Each S1-S13
arm deliberately pins one toggle and leaves the rest at their `vuln` default, so
without these rows the hardened build that [Run modes](#run-modes) tells you to run
would have no coverage at all.

<a id="detection-rules--automate-the-hunt"></a>

## Detection rules

[`detection/`](detection/README.md) ships 45 [Semgrep](https://semgrep.dev)
rules that flag these patterns in your own MCP server source, not just this
lab's. There is one per code shape above, with Python siblings where the
JavaScript spelling cannot parse as Python, plus Go, Rust, Kotlin, Java, Ruby, PHP, C#,
and Swift language packs. Eleven of them run against Python as well as
JavaScript/TypeScript, which matters because the reference MCP SDKs ship in both.

Measured against this lab's own source, the rules flag 7 of the 13 scenarios (S1, S2,
S6, S7, S8, S12, S13). The other six sit behind a runtime toggle or a
transport-header shape. Against the official `@modelcontextprotocol/sdk` the ruleset
produces zero findings, measured with a planted canary that proves the scan reached
the tree. The per-scenario breakdown is in [`detection/README.md`](detection/README.md)
and the measurement notes are in [`docs/detection-notes.md`](docs/detection-notes.md).

Drop it into your own MCP server's CI as a GitHub Action. Findings upload to
your repo's Security tab, so the calling workflow needs
`security-events: write`:

```yaml
permissions:
  security-events: write   # only needed for the SARIF upload

steps:
  - uses: WRG-11/mcp-objauthz-lab@main
    with:
      path: src/   # your MCP server source
```

## Run modes

The lab is a multi-tenant note server exposing eighteen MCP tools and one MCP resource
across thirteen independent BOLA scenarios. Each scenario has its own toggle, `LAB_S1`
to `LAB_S13`, and every toggle defaults to `vuln`. Run all scenarios in their fixed state:

```bash
# Linux / macOS
LAB_S1=fixed LAB_S2=fixed LAB_S3=fixed LAB_S4=fixed LAB_S5=fixed LAB_S6=fixed LAB_S7=fixed LAB_S8=fixed LAB_S9=fixed LAB_S10=fixed LAB_S11=fixed LAB_S12=fixed LAB_S13=fixed npm start

# Windows PowerShell
$env:LAB_S1='fixed'; $env:LAB_S2='fixed'; $env:LAB_S3='fixed'; $env:LAB_S4='fixed'; $env:LAB_S5='fixed'; $env:LAB_S6='fixed'; $env:LAB_S7='fixed'; $env:LAB_S8='fixed'; $env:LAB_S9='fixed'; $env:LAB_S10='fixed'; $env:LAB_S11='fixed'; $env:LAB_S12='fixed'; $env:LAB_S13='fixed'; npm start
```

What each toggle changes, and how to isolate one scenario, is in
[`docs/configuration.md`](docs/configuration.md).

## More documentation

- [`docs/scenarios.md`](docs/scenarios.md): one walkthrough per scenario.
- [`docs/hunt-checklist.md`](docs/hunt-checklist.md): what to read when auditing a real multi-tenant MCP server.
- [`docs/architecture.md`](docs/architecture.md): the file map and the identity model.
- [`docs/configuration.md`](docs/configuration.md): the environment variables.
- [`docs/detection-notes.md`](docs/detection-notes.md): what the rules were measured to catch and miss.

## Scenario reference

Rule messages link to the headings below. Each one points to its challenge and walkthrough.

## Scenario S1 — Missing org-scope check (the original)

Inconsistent authorization: find the single outlier. `note_delete`, CWE-639 / CWE-862, toggle `LAB_MODE` / `LAB_S1`.
[Challenge](challenges/s1.md), [walkthrough](docs/scenarios.md#scenario-s1--missing-org-scope-check-the-original).

## Scenario S2 — Scope-as-param

Client-supplied scope trusted as authorization. `note_search`, CWE-639, toggle `LAB_S2`.
[Challenge](challenges/s2.md), [walkthrough](docs/scenarios.md#scenario-s2--scope-as-param).

## Scenario S3 — List→get asymmetry

List→get asymmetry: batch skips per-object check. `note_batch_get`, CWE-862, toggle `LAB_S3`.
[Challenge](challenges/s3.md), [walkthrough](docs/scenarios.md#scenario-s3--listget-asymmetry).

## Scenario S4 — Wildcard/sentinel bypass

Wildcard/sentinel value bypasses scope filter. `note_export`, CWE-639, toggle `LAB_S4`.
[Challenge](challenges/s4.md), [walkthrough](docs/scenarios.md#scenario-s4--wildcardsentinel-bypass).

## Scenario S5 — Role/token-type bypass

Role/token-type bypass: admin-named tool, no role check. `note_admin_get`, CWE-863, toggle `LAB_S5`.
[Challenge](challenges/s5.md), [walkthrough](docs/scenarios.md#scenario-s5--roletoken-type-bypass).

<a id="scenario-s6--foreign-parent"></a>

## Scenario S6 — Foreign-parent injection

Foreign-parent injection: create trusts a caller-supplied org. `note_create_in_org`, CWE-639, toggle `LAB_S6`.
[Challenge](challenges/s6.md), [walkthrough](docs/scenarios.md#scenario-s6--foreign-parent-injection).

## Scenario S7 — Unscoped query

Unscoped query: tenant key omitted from the filter (the real-world shape). `note_get_by_query`, CWE-639, toggle `LAB_S7`.
[Challenge](challenges/s7.md), [walkthrough](docs/scenarios.md#scenario-s7--unscoped-query).

## Scenario S8 — Resource-URI-as-scope

Resource-URI-as-scope: the resources/read surface, not tools/call. `note://{token}/{orgId}/{noteId}`, CWE-639, toggle `LAB_S8`.
[Challenge](challenges/s8.md), [walkthrough](docs/scenarios.md#scenario-s8--resource-uri-as-scope).

## Scenario S9 — Authz-from-client-round-tripped-value

Authz-from-client-round-tripped-value: an editable share grant. `note_share_prepare`, `note_share_redeem`, CWE-639, toggle `LAB_S9`.
[Challenge](challenges/s9.md), [walkthrough](docs/scenarios.md#scenario-s9--authz-from-client-round-tripped-value).

## Scenario S10 — Forwarded-header-as-scope

Forwarded-header-as-scope: a trusted request header (HTTP transport). `note_get_scoped`, CWE-639 / CWE-290, toggle `LAB_S10`.
[Challenge](challenges/s10.md), [walkthrough](docs/scenarios.md#scenario-s10--forwarded-header-as-scope).

<a id="scenario-s11--xff-quota-bypass"></a>

## Scenario S11 — Forwarded-header quota bypass

X-Forwarded-For quota bypass: a trusted request header for rate limiting (HTTP transport). `note_create_limited`, CWE-639 / CWE-290, toggle `LAB_S11`.
[Challenge](challenges/s11.md), [walkthrough](docs/scenarios.md#scenario-s11--forwarded-header-quota-bypass).

## Scenario S12 — Batch resolve without a per-item check

Batch/bulk endpoint BOLA: multi-object endpoint without per-item tenant filter. `note_batch_resolve`, CWE-639 / CWE-862, toggle `LAB_S12`.
[Challenge](challenges/s12.md), [walkthrough](docs/scenarios.md#scenario-s12--batch-resolve-without-a-per-item-check).

<a id="scenario-s13--jwt-token-scope-confusion"></a>

## Scenario S13 — Token scope claim trusted as permission

JWT/token scope confusion: token's scope/aud claim vs actual permissions mismatch. `note_get_by_token_scope`, CWE-639 / CWE-290, toggle `LAB_S13`.
[Challenge](challenges/s13.md), [walkthrough](docs/scenarios.md#scenario-s13--token-scope-claim-trusted-as-permission).

## Safety / scope

This server is vulnerable by design. Do not deploy it on a reachable network or use
it as a starting point for real code. Run it locally for learning only.

Everything in it is synthetic. The orgs and users are made up, and so are their notes
and tokens; there is no real target. The PoC never makes a network request. It only
spawns the local server process over stdio.

## Contributing

The most useful contribution to a detection ruleset is a false positive:
a rule that fires on correctly authorized code. A gate wider than the defect
it targets gets switched off, and a switched-off rule protects nothing, so
those are treated as real defects here. Misses are just as welcome; the rules
catch 7 of the 13 scenarios against this lab's own source and
[`detection/README.md`](detection/README.md) says why.

There is an issue template for each. [`CONTRIBUTING.md`](CONTRIBUTING.md) has
the fixture convention and the exact-count CI gate. It also describes the
multi-language rule trap that costs an afternoon if you meet it the hard way.

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
Security reports go through [`SECURITY.md`](SECURITY.md). Please do not
report the planted flaws; they are the point.

## Citing this

[`CITATION.cff`](CITATION.cff), or use GitHub's "Cite this repository" button.

## License

[MIT](LICENSE).
