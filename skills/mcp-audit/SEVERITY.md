# Default severity per finding type

Every finding the [`mcp-audit` skill](SKILL.md) records carries one `finding_id`
from the table below and starts at that row's severity. The severity decides the
disclosure channel when the server belongs to someone else
([`references/disclosure.md`](references/disclosure.md)).

A default can be overridden when context calls for it - a tautological
description on a tool that mints credentials is not Info - but the override is
written down next to the finding, never applied silently. See
[Overrides](#overrides).

## Buckets

| Bucket | Meaning |
|---|---|
| Critical | A remote or unauthenticated party gets credentials, code execution or other users' data, with no further condition. |
| High | Needs a condition (a foothold, a specific input, a non-default setting), then reaches beyond its intended scope (another tenant's data, files or hosts it should not touch) or above its privileges. Corrupting stored data also counts. |
| Medium | Degrades safety, observability or trust without enabling compromise on its own. |
| Low | Consistency, hygiene and test gaps with no security or correctness effect in normal use. |
| Info | Documentation, discoverability and decay observations. |

## Matrix

The examples are illustrative shapes, not quotes from any audited server.

| finding_id | Category | Finding | Default | Why | Example |
|---|---|---|---|---|---|
| `DISC-001` | Discoverability | Description restates the function name (1/5) | Info | Hurts an agent's choice of tool; no security or correctness effect | `get_status` described as "Get status." |
| `DISC-002` | Discoverability | No trigger phrases | Info | Lowers the chance an agent picks the tool | "Returns the data." with no "use when" |
| `DISC-003` | Discoverability | No when-to-use guidance | Info | Same effect as DISC-002 | Describes the result but never when to call |
| `DISC-004` | Discoverability | Return shape undocumented | Info | Callers must read the source to know the fields | "Gets the user." with no field list |
| `DISC-005` | Discoverability | Name and description identical | Info | Usually a stub that was never filled in | Name `get_session`, description `get_session` |
| `SHAPE-001` | Return shape | Common envelope on most tools, raw dicts on some | Low | Callers need per-tool branches | 28 of 32 tools use the envelope, 4 return raw dicts |
| `SHAPE-002` | Return shape | Raw list or string, no envelope at all | Low | Same as SHAPE-001, and harder to extend later | `list_users` returns `["a", "b"]` |
| `SHAPE-003` | Return shape | Error signalled only by the presence of an `error` key | Low | Callers must test for a key instead of one flag | `{"error": "not found"}` on failure, `{"data": ...}` on success |
| `SHAPE-004` | Return shape | Empty result returned on error | Medium | Failure is invisible to the caller | `except Exception: return {}` |
| `SHAPE-005` | Return shape | Result cast past the declared output schema | Low | The type checker found a real mismatch and the handler silenced it | `return result as unknown as CallToolResult` in a TypeScript handler |
| `NAME-001` | Naming | Case convention broken | Info | Cosmetic inconsistency | `getUser` beside `delete_user` |
| `NAME-002` | Naming | Family prefix missing on one member | Info | Families drift once one member breaks the pattern | `memory_get`, `memory_set`, `recall_last` |
| `NAME-003` | Naming | Different verbs for the same operation | Info | Callers must learn a verb per tool | `get_note`, `fetch_folder`, `read_tag` |
| `ERR-001` | Error handling | Bare exception from a tool on a surface that otherwise returns structured errors | Low | Inconsistent, but recoverable | `raise RuntimeError("bad input")` |
| `ERR-002` | Error handling | Mix of raising and structured errors across the surface | Low | Same as ERR-001 at surface level | 5 tools raise, 27 return a structured error |
| `ERR-003` | Error handling | Error text leaks a filesystem path or stack trace | Medium | Reveals server layout to the client | `{"error": "open('/srv/app/.config/secrets.json')"}` |
| `ERR-004` | Error handling | Exception swallowed and success reported | Medium | Success and silent failure look identical | `except: pass` then `return {"ok": True}` |
| `TEST-001` | Tests | Read-only tool with no MCP-layer test | Low | Refactors can break it unnoticed; failures are visible | Only the underlying function is tested |
| `TEST-002` | Tests | MCP-layer test with no assertion on the result | Low | Catches import errors only | `def test_tool(): tool()` |
| `TEST-003` | Tests | Mutation tool with no test | Medium | Unknown blast radius; bad writes are harder to undo than bad reads | `archive_project` appears in no test |
| `TEST-004` | Tests | No test at any layer | Low | Broader form of TEST-001, listed separately for ranking | The tool name never appears under `tests/` |
| `DECAY-001` | Decay | No CHANGELOG, docs, consumer or test | Low | Remove or deprecate candidate | `export_v1`, untouched for a year |
| `DECAY-002` | Decay | Three of the four signals missing | Info | Soft-deprecate candidate; recheck later | Mentioned once in the CHANGELOG, nothing else |
| `DECAY-003` | Decay | Never mentioned in the CHANGELOG | Info | Undocumented addition | Added in a commit the CHANGELOG never records |
| `STATE-001` | State | Writes without write-temp-then-rename or a transaction | Medium | A crash mid-write leaves a truncated file | `fs.writeFile(store, data)` straight onto the live file |
| `STATE-002` | State | No lock around load, mutate, save | Medium | Overlapping calls lose writes silently | Two concurrent `create_item` calls both load before either saves |
| `STATE-003` | State | No test of persistence across a restart | Low | A storage change can break persistence unnoticed | Every test runs inside one server instance |
| `STATE-004` | State | One tool's writes visible to another in undocumented ways | Medium | Trust-degrading on shared deployments; see AUTHZ rows when it crosses tenants | A cache keyed by object id but not by user |
| `SEC-001` | Security | Credential committed to source or shipped in the package | Critical | Compromise on install | `API_KEY = "sk-..."` at module level |
| `SEC-002` | Security | Tool returns environment variables or secrets | Critical | Exfiltration through a normal call | `return {"env": dict(os.environ)}` |
| `SEC-003` | Security | Shell command built from tool arguments | Critical | Command injection | `subprocess.run(f"ls {path}", shell=True)` |
| `SEC-004` | Security | Fetch of an arbitrary URL with no allowlist | High | Server-side request forgery, conditional on the network | `url: str` passed straight to the HTTP client |
| `SEC-005` | Security | Path traversal in a file tool | High | Reads or writes outside the intended directory | `Path(base) / user_input` with no resolved-path check |
| `SEC-006` | Security | Mutation tool with no authentication gate | High | Any client of the server can mutate; Medium behind a documented read-only proxy | `delete_user` with no auth middleware |
| `SEC-007` | Security | Query built from tool arguments | High | Injection into the backing store | `f"SELECT * FROM users WHERE id={uid}"` |
| `SEC-008` | Security | No rate limit on an expensive tool | Medium | Denial of service, not compromise | A full repository scan on every call |
| `SEC-009` | Security | Responses expose versions, paths or internal hostnames | Medium | Reconnaissance aid | Every response carries `host` and `data_dir` |
| `AUTHZ-001` | Authorization | Object read by id with no check that it belongs to the caller's tenant | High | Cross-tenant read; the bug class this repository's scenarios teach | `get_note(note_id)` loads by id after checking only that the caller is logged in |
| `AUTHZ-002` | Authorization | Object written, deleted or created under a parent the caller does not own | High | Cross-tenant write or injection into another tenant | `create_note(folder_id)` accepts another tenant's folder |
| `AUTHZ-003` | Authorization | A client-supplied value used as the authorization scope | High | The caller chooses whose data the query runs against | `org_id` argument, a URI segment or a forwarded header used to scope the query |
| `AUTHZ-004` | Authorization | A value produced by an earlier call trusted on redemption without a re-check | High | Authorization moves to the client; signing the value does not fix it | A cursor or grant decoded and served without checking the current session |

`AUTHZ-*` findings are confirmed the way the
[hunt checklist](https://github.com/WRG-11/mcp-objauthz-lab/blob/main/docs/hunt-checklist.md)
describes: as one tenant, request another tenant's object. A hit from
[the lab's Semgrep rules](https://github.com/WRG-11/mcp-objauthz-lab/tree/main/detection/semgrep)
that has not been confirmed is recorded as a lead in the report, not as a finding.

## Overrides

Write an override next to the finding as `OVERRIDE: escalated` or
`OVERRIDE: de-escalated`, followed by the reason:

- `DISC-001` escalated to Low: the tautological description is on a tool that
  issues tokens, and agents call it by mistake.
- `SEC-006` de-escalated to Medium: the mutation tool only runs behind a
  documented development flag, and the README warns against production use.
- `STATE-001` or `STATE-002` de-escalated to Low when the fix is a small public
  pull request that the maintainer can judge from the diff alone (see
  "the disclosure is the patch" in
  [`references/disclosure.md`](references/disclosure.md)).
- `STATE-004` escalated to High when the leak crosses a tenant boundary; it is
  then usually an `AUTHZ-*` finding.
- `AUTHZ-*` escalated to Critical when no authentication is needed to reach the
  tool at all.

`SEC-001`, `SEC-002` and `SEC-003` are floors: never de-escalate them.

## Adding a row

When a finding matches no row, add one in the same pull request as the audit
that needed it. Keep ids zero-padded and contiguous within a prefix, and give the
row an example shape. Every finding must cite a row, so a row has to exist before
a finding can use it.
