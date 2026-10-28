# Detection measurement notes

What the rules were measured to catch and miss, and the two false-positive
hardenings. The rule list and how to run it are in
[`detection/README.md`](../detection/README.md).

Honestly documented, and re-measured in this release: the earlier claim that
the rules "catch 5 of 7 scenarios" against this lab's own source implied the
S1/S5 rules miss real-world bugs. They do not. On production-shaped files —
no toggle, guard simply absent — both fire exactly as designed; the only code
they go quiet on is a handler where the guard is *written but gated behind a
runtime toggle*, i.e. this lab's own scaffolding (see the linked README for
the measured decision and the fixtures pinning it). Measured again on
2026-10-28, a rule reports a line inside the handlers of **8 of the 13
scenarios (S2, S4, S6, S7, S8, S9, S10, S13)**. The remaining five stay
quiet: S1, S3, S5 and S12 have their fix in the same handler behind a runtime
toggle (this lab's own scaffolding), and S11 routes the header through a
longer flow than its rule follows — see
[`detection/README.md`](../detection/README.md) for the per-scenario breakdown,
the two earlier miscounts it corrects, and the fixtures pinning it. S9 has no
dedicated rule: the existing `mcp-missing-object-authz-check` (S1's rule)
already catches its vulnerable shape, since the fix path is a plain
`$OBJ = store.get...(); ...; return ok($OBJ)` span with no guard call in
between — see [`detection/README.md`](../detection/README.md) for the measured
caveat (it only catches the assignment-carrying spelling, not an inline
`return ok(store.getNote(...))` with no local variable). Against the
official `@modelcontextprotocol/sdk` the ruleset produces **zero findings**,
measured with a planted canary proving the scan actually reached the tree
(semgrep silently skips `node_modules`, so an unverified `0` is not a
result).

Two rules were hardened in this release against false positives found in a
9-repo audit:
- `mcp-authz-scope-from-request-header` (+ `-py`): now requires the header
  value to reach an **authorization decision** (store call selecting tenant
  scope), not merely be read. Two-way canary: FIRE on scope decision, SILENT
  on logging-only read.
- `mcp-wildcard-sentinel-scope-bypass`: now requires the wildcard to be in an
  **authorization bypass context** (gates scope widening), not a textual
  comparison. Two-way canary: FIRE on authz bypass, SILENT on markup/UI filter.

Real-capture fixtures from the audit validate both hardenings: `xff-for-logging.js/.py`
(SILENT), `wildcard-in-markup.js` (SILENT), and `xff-for-ratelimit.js/.py` (FIRE for
the new S11 rule and its -py sibling).
