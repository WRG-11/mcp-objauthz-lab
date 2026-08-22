<!--
CONTRIBUTING.md has the full detail. This is the short version: the checks
below are the ones that have actually caught mistakes in this repo.
-->

## What this changes

<!-- One or two sentences. Say why, not what — the diff shows the what. -->

## Checks

- [ ] `npm test` and `npm run poc` pass
- [ ] Semgrep fixture count matches the `want` value in `.github/workflows/ci.yml`
- [ ] The rules still find the planted bugs in `src/` (`semgrep --config detection/semgrep/mcp-object-authz.yml src/`)

## If this touches a detection rule

- [ ] The fixture carries **both** halves — a `ruleid:` case and an `ok:` case.
      A rule that flags everything passes a catch-only test.
- [ ] Ran it against real third-party code, not just the fixture. The official
      `@modelcontextprotocol/sdk` in `node_modules/` is 168 files of it and
      currently produces zero findings; a new rule should keep it that way or
      explain why not.
- [ ] If the rule declares more than one language, every pattern parses in
      **all** of them. Semgrep marks the whole rule invalid otherwise, and the
      scan still exits 0 while reporting nothing.

## If this adds a scenario

- [ ] Planted bug gated by its own `LAB_S<n>` env var
- [ ] Challenge with a concrete exploit goal and a verification step
- [ ] Exploit in `poc/`
- [ ] Either a detection rule, or a note in `detection/README.md` saying which
      existing rule covers it — or that none does
