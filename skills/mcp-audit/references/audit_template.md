# MCP tool audit - `<server-name>` (<YYYY-MM-DD>)

> Read-only audit of the MCP tool surface of `<server-name>` at `<repository>@<commit>`
> (package `<name>@<version>`). No code was changed. The result is a short list of
> fixes of an hour or less and a deferred backlog.
>
> Auditor: <name>. Variant: full / short (fewer than ten tools).

---

## 0. Target

| Field | Value |
|---|---|
| Repository and commit | `<owner/repo>@<sha>` |
| Package and version | `<name>@<version>` |
| Maintained | yes / archived / moved to `<where>` |
| Multi-tenant | yes / no (decides whether section 7 runs) |
| Stateful | yes / no (decides whether section 6 runs) |

---

## 1. Inventory

Total: N tools, R resources, P prompts, across M modules.

| # | Tool | Location | Description (first sentence) | Arguments | Returns |
|---|---|---|---|---|---|
| 1 | `tool_a` | `server.py:NN` | `...` | `(path: str)` | dict |
| 2 | `tool_b` | `server.py:NN` | `...` | `()` | str |

---

## 2. Discoverability (1-5 per tool)

- 5 - trigger phrases, when-to-use guidance and the return shape
- 4 - two of the three
- 3 - one of the three
- 2 - present, but says nothing beyond the name
- 1 - restates the name

| Tool | Score | Why (scores below 5 only) |
|---|---|---|
| `tool_a` | 5 | - |
| `tool_b` | 4 | Trigger phrases and return shape; no when-to-use |
| `tool_c` | 1 | "Get C." |

Average: `<sum>/<N>` = <X.YZ>. Distribution: 5: <n> · 4: <n> · 3: <n> · 2: <n> · 1: <n>.

---

## 3. Consistency

### 3.1 Return shape

| Idiom | Count | Tools |
|---|---|---|
| Common envelope | <n>/<N> | `tool_a`, ... |
| Raw dict | <n> | `tool_x` |
| Raw list or string | <n> | `tool_y` |
| Raises on error | <n> | `tool_z` |
| Error by key presence | <n> | `tool_w` |

### 3.2 Naming

- Case convention: consistent / exceptions: `...`
- Family prefixes: `...` (members missing the prefix: `...`)
- Verb collisions: `...`

### 3.3 Errors

| Tool | Error path |
|---|---|
| `tool_a` | raises `ValueError` |
| `tool_b` | structured error result |
| `tool_c` | returns an empty result |

---

## 4. Tests

| Tool | Tested at | Coverage |
|---|---|---|
| `tool_a` | MCP layer | asserts the result |
| `tool_b` | function only | none at the MCP layer |
| `tool_c` | nowhere | - |

Summary: <n>/<N> tools have an MCP-layer test that asserts the result.

---

## 5. Decay

| Tool | CHANGELOG | Docs | Consumer | Test | Risk |
|---|---|---|---|---|---|
| `tool_a` | yes | yes | yes | yes | none |
| `tool_d` | no | no | no | no | high |
| `tool_e` | yes | no | no | smoke | medium |

---

## 6. State handling (stateful servers only)

| Check | Result | Evidence |
|---|---|---|
| Atomic writes | yes / no | `store.js:NN` |
| Lock around load, mutate, save | yes / no | `...` |
| Persistence tested across a restart | yes / no | `...` |
| Undocumented cross-tool visibility | none / `...` | `...` |

---

## 7. Object-level authorization (multi-tenant servers only)

Rule scan: `semgrep --config detection/semgrep/ <path>` from
`mcp-objauthz-lab@<sha>`: <n> hits, <n> confirmed, <n> rejected after reading the
handler.

| Tool or resource | Checklist item | Lead source | Confirmed by | Result |
|---|---|---|---|---|
| `get_note` | object read by id, membership only | rule `<rule-id>` | tenant B read tenant A's note | `AUTHZ-001` |
| `create_note` | foreign parent | checklist | tenant B created a note in A's folder | `AUTHZ-002` |
| `list_notes` | - | rule `<rule-id>` | scoped by session; rule hit rejected | none |

---

## 8. Findings

| # | finding_id | Severity | Tool | Finding | Why this bucket |
|---|---|---|---|---|---|
| F-001 | `AUTHZ-001` | High | `get_note` | ... | default |
| F-002 | `DISC-001` | Low | `issue_token` | ... | `OVERRIDE: escalated` - issues credentials |

Novelty checks (for every finding reported as new): the queries run and the
number of results each returned.

---

## 9. Decision gate

### Numbers

- Tools: N
- Average discoverability: <X.YZ>/5
- On the common result shape: <n>/<N>
- MCP-layer tests that assert the result: <n>/<N>

### This week (an hour or less each, named tools)

1. <fix> - for example "add the missing tenant check to `get_note` (`tools.js:NN`)" - 20 min
2. <fix> - for example "rewrite the descriptions of `get_status` and `get_c`" - 30 min

### Backlog (more than an hour each)

3. <fix>
4. <fix>
5. <fix>

### Decay candidates

- `tool_d` - remove
- `tool_e` - soft-deprecate

---

## Maintainer checklist

- [ ] Section 1: the inventory count matches
- [ ] Section 2: the 1/5 descriptions really say nothing
- [ ] Section 7: each confirmed authorization finding reproduces
- [ ] Section 9: one or two fixes picked for this week
- [ ] Backlog items filed as issues
