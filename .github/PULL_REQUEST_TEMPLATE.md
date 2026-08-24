<!--
CONTRIBUTING.md has the full detail. This is the short version: the checks
below are the ones that have actually caught mistakes in this repo.
-->

## What this changes

<!-- One or two sentences. Say why, not what — the diff shows the what. -->

## Checks

- [ ] `npm test` and `npm run poc` pass
- [ ] Semgrep fixture count matches the `want` value in `.github/workflows/ci.yml`
- [ ] The rules still find the planted bugs in `src/` (`semgrep --config detection/semgrep/ src/`)

## If this touches a detection rule

- [ ] The fixture carries **both** halves — a `ruleid:` case and an `ok:` case.
      A rule that flags everything passes a catch-only test.
- [ ] Ran it against real third-party code, not just the fixture — **and proved
      the scan reached it**. Copy `node_modules/@modelcontextprotocol/sdk`
      somewhere outside `node_modules/` first (semgrep skips that directory
      even when told otherwise, and a skipped tree reports a clean `0`).
      Scan the copy, then plant a known-violating snippet inside it and
      rescan: if the canary does not fire, your `0` is not a result.
      Current baseline: 344 files of the official SDK, zero findings.
- [ ] If the rule declares more than one language, every pattern parses in
      **all** of them. Semgrep marks the whole rule invalid otherwise, and the
      scan still exits 0 while reporting nothing.

## If this adds a scenario

- [ ] Planted bug gated by its own `LAB_S<n>` env var
- [ ] Challenge with a concrete exploit goal and a verification step
- [ ] Exploit in `poc/`
- [ ] Either a detection rule, or a note in `detection/README.md` saying which
      existing rule covers it — or that none does
