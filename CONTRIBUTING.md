# Contributing

Thanks for looking. This repo is two things that need different kinds of help:

- a **deliberately vulnerable MCP server** (`src/`) with nine planted bugs and
  a challenge per bug (`challenges/`), and
- a **Semgrep ruleset** (`detection/`) that finds those same bugs in real MCP
  servers.

The most useful contributions are usually about the second one.

## The one thing to know first

`src/` is **vulnerable on purpose**. Please do not open an issue reporting the
planted flaws — they are documented in the README and each has a challenge
walking through it. `SECURITY.md` explains what an *unintended* problem looks
like and how to report it privately.

## Reporting a false positive or a miss

This is the highest-value report for a detection ruleset, and there is an issue
template for each.

A rule that fires on correct code gets switched off, and a switched-off rule
protects nothing — so a false positive is treated as a real defect here, not
noise. When reporting one, the minimal reproducing snippet matters more than
the explanation.

A miss (a real authorization bug the rules walked past) is just as welcome.
The rules currently catch 7 of the 9 scenarios against this lab's own source;
`detection/README.md` explains why, honestly, and that limitation is a
starting point rather than a defence.

## Adding or changing a rule

Every rule ships with a fixture, and the fixture carries **both halves**:

```javascript
async function vulnDelete({ token, id }) {
  const note = store.getNote(id);
  // ruleid: mcp-missing-object-authz-check
  store.deleteNote(note.id);
}

async function fixedDelete({ token, id }) {
  const note = store.getNote(id);
  requireOrgAccess(session, note);
  // ok: mcp-missing-object-authz-check
  store.deleteNote(note.id);
}
```

Testing only that a rule catches the violation is half a test: a rule that
flags *everything* would pass it. The `ok:` case is what proves the rule still
lets correct code through.

CI asserts an **exact** finding count across all fixtures rather than a
minimum, so adding a rule or a fixture case means updating that number in
`.github/workflows/ci.yml`. That is deliberate — a rule that quietly starts
matching more than it should shows up as a count mismatch instead of blending
in.

### If your rule targets more than one language

Semgrep requires every pattern in a rule to parse in **every** language the
rule declares. A pattern that is valid Python but not JavaScript makes the
whole rule invalid — and the scan still exits 0 while silently reporting
nothing. If a language needs its own syntax, give it its own rule (see
`mcp-client-supplied-scope-overrides-session-py-ternary` for the shape).

Every JavaScript/TypeScript shape also has Python coverage: either the rule
declares `python` directly (three do), or it has a `-py` sibling rule
carrying the Python spelling of the same defect (`=>` arrows, object
literals and `registerTool` callbacks cannot parse as Python, and Python's
equivalents cannot parse as JavaScript — merging would invalidate the whole
rule). When adding a pattern to a multi-language rule, remember that every
pattern must parse in **every** declared language, and that a pattern which
fails to parse silences the entire rule while scans still exit 0.

### Before opening the PR

```bash
npm test                                        # the lab's own unit tests
npm run poc                                     # the exploit walkthroughs

pip install semgrep
semgrep --config detection/semgrep/ \
        detection/semgrep/fixtures/ --no-git-ignore --quiet --json \
        --output=/tmp/fixtures.json             # count must match ci.yml

semgrep --config detection/semgrep/ src/
```

The last one is the dogfood check: the rules must keep finding the planted
bugs in this lab's own source. CI runs it too, and there a **non-zero exit is
the success case** — `src/` is supposed to be vulnerable.

## Adding a scenario

A new scenario needs four things, and the fourth is the one people forget:

1. a planted bug in `src/tools.js`, gated by its own `LAB_S<n>` env var so the
   other scenarios stay independent,
2. a challenge in `challenges/s<n>.md` with a concrete exploit goal and a
   verification step ("the exploit succeeds when …"),
3. an exploit in `poc/`,
4. either a detection rule **or** an honest note in `detection/README.md`
   saying which existing rule covers it, or that none does.

S6 is covered by the S2 rule — same code shape, different tool — and saying so
is more useful than shipping a redundant rule.

## Style

- Commit messages: imperative mood, and say *why* rather than *what* when the
  what is visible in the diff.
- No AI-assistant co-author trailers.
- English throughout, including comments and commit messages.
