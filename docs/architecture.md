# How it is built

| File | Role |
|---|---|
| [`src/store.js`](../src/store.js) | In-memory multi-tenant seed data: 3 tenant orgs (*Acme/Alice*, *Globex/Bob*, *Initech/Carol*, 2 notes each) + 1 admin org (*Platform Ops/Dana*, no notes). |
| [`src/auth.js`](../src/auth.js) | `resolveSession(token)` → server-trusted `{ user, org, role }`; `requireOrgAccess(session, object)` — the object-level check; `requireAdminRole(session)` — the role check. |
| [`src/tools.js`](../src/tools.js) | Eighteen tools plus one resource (`note://{token}/{orgId}/{noteId}`). Thirteen planted-bug handlers (one per scenario, S1-S13). |
| [`src/server.js`](../src/server.js) | Stdio MCP server. Reads `LAB_MODE`/`LAB_S1..S13` env vars, passes a `modes` object to `registerTools`. |
| [`src/http-server.js`](../src/http-server.js) | Streamable-HTTP MCP server (for S10/S11). Same tools/store, transports headers via `extra.requestInfo.headers`. |
| [`poc/exploit.js`](../poc/exploit.js) | MCP client running the 38-row two-way gate: all 13 scenarios in isolation, plus the all-`fixed` hardened build. |
| [`test/`](../test/) | `node --test` suite (74 tests): `auth.js`/`store.js` unit tests with no MCP transport, `docs-consistency` (docs and citation checked against the code), `ci-hardening` (the action's and workflows' supply-chain and privilege rules), and `security-hardening` plus `readme-poc-output`, which start the server. |

**Identity model (deliberate simplification).** Each tool takes a bearer `token`
the server resolves to a fixed user, org, and role. The caller never asserts its
own org or role — only presents a token. In a production MCP server this identity
would come from the transport / OAuth layer; the lab passes it per call so it
stays a single process and the authorization logic is explicit and easy to read.
