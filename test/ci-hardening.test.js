// Supply-chain and privilege hygiene for the action this repo publishes and
// the workflows that test it.
//
// The lab's *server* is vulnerable by design. The composite action in
// action.yml is not: other people run it in their own CI, with their own
// tokens. These assertions hold the parts of that surface that nothing else
// checks -- a green CI run proves the action works, not that it is safe to
// call.
//
// Deliberately dependency-free: no YAML parser, just the few shapes these
// files actually use. Each helper says which shape it understands, and the
// sanity tests fail loudly if a file stops matching it, so a parser that
// silently sees nothing cannot pass for a clean file.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => readFileSync(join(root, rel), "utf8");

const workflowFiles = readdirSync(join(root, ".github/workflows"))
  .filter((f) => /\.ya?ml$/.test(f))
  .map((f) => `.github/workflows/${f}`);
const actionAndWorkflows = ["action.yml", ...workflowFiles];

/**
 * Every `run:` body in a workflow/action file, as { file, line, body }.
 * Understands `run: <inline>` and `run: |` / `run: >` block scalars, where the
 * block is every following line indented deeper than the `run:` key (or blank).
 */
function runBlocks(rel) {
  const lines = read(rel).split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(\s*)(?:-\s+)?run:\s*(.*)$/);
    if (!m) continue;
    const keyCol = lines[i].indexOf("run:");
    const rest = m[2].trim();
    if (rest && !/^[|>][-+]?$/.test(rest)) {
      out.push({ file: rel, line: i + 1, body: rest });
      continue;
    }
    const body = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const l = lines[j];
      if (l.trim() === "") { body.push(l); continue; }
      if (l.search(/\S/) <= keyCol) break;
      body.push(l);
    }
    out.push({ file: rel, line: i + 1, body: body.join("\n") });
    i = j - 1;
  }
  return out;
}

test("sanity: the run-block reader sees the steps these files actually have", () => {
  // action.yml has three shell steps (install, scan, fail-on-findings); every
  // workflow here has at least one. Zero would mean the reader broke, not
  // that the files are clean.
  assert.ok(runBlocks("action.yml").length >= 3, "expected >= 3 run: steps in action.yml");
  for (const wf of workflowFiles.filter((f) => f.endsWith("ci.yml"))) {
    assert.ok(runBlocks(wf).length >= 3, `expected >= 3 run: steps in ${wf}`);
  }
});

// ── no template expressions inside shell ───────────────────────────────────
// `${{ ... }}` is substituted into the script text BEFORE bash parses it, so
// a value containing `"; curl … | sh; "` becomes code. For the composite
// action that value is whatever the calling workflow passes as `path:` --
// possibly derived from a PR title or branch name. GitHub's hardening guide:
// hand expressions to the step through `env:` and reference "$VAR" instead.
// Held for every run: block, not only `inputs.*`, so the rule stays one
// sentence and a reviewer never has to decide which contexts are "trusted".
test("no ${{ }} expression is interpolated into a run: script", () => {
  const offenders = actionAndWorkflows
    .flatMap(runBlocks)
    .filter((b) => b.body.includes("${{"))
    .map((b) => `${b.file}:${b.line}`);
  assert.deepEqual(
    offenders,
    [],
    `template expressions inside run: (move them to env:) at ${offenders.join(", ")}`,
  );
});

// ── semgrep is pinned, in one place, and something keeps the pin current ───
// `pip install semgrep` installs whatever was published that morning, into
// every consumer's CI. The rule set's behaviour is a function of the engine
// version (the fixture count below in ci.yml is exact), so an unpinned engine
// can change what the action reports without a single commit here. One
// requirements file is the pin; dependabot moves it, CI proves the move.
const SEMGREP_REQ = "detection/requirements.txt";

test("every semgrep install reads the single pinned requirements file", () => {
  const installs = actionAndWorkflows
    .flatMap(runBlocks)
    .filter((b) => /pip3?\s+install/.test(b.body) && /semgrep|requirements/.test(b.body));
  assert.ok(installs.length >= 2, "expected the action and ci.yml to install semgrep");
  for (const b of installs) {
    assert.ok(
      b.body.includes(SEMGREP_REQ) && /pip3?\s+install\b[^\n]*\s-r\s/.test(b.body),
      `${b.file}:${b.line} installs semgrep without -r ${SEMGREP_REQ}`,
    );
  }
});

test("the requirements file pins semgrep to an exact version", () => {
  const req = read(SEMGREP_REQ);
  assert.match(req, /^semgrep==\d+\.\d+\.\d+\s*$/m, `${SEMGREP_REQ} must pin semgrep==X.Y.Z`);
});

test("dependabot watches the semgrep pin", () => {
  const cfg = read(".github/dependabot.yml");
  assert.match(
    cfg,
    /package-ecosystem:\s*"?pip"?\s*\n\s*directory:\s*"?\/detection"?/,
    "no dependabot pip entry for /detection -- the pin would rot silently",
  );
});

// ── installs are reproducible: a committed lockfile, installed with npm ci ──
// package.json pins the two direct dependencies exactly, but their ~90
// transitive packages floated on every `npm install` -- package-lock.json had
// been in .gitignore since the first commit, with no stated reason. The lock
// carries an integrity hash per package; `npm ci` refuses to install anything
// that does not match it, and fails if package.json and the lock disagree.
test("package-lock.json is committed, not ignored, and agrees with package.json", () => {
  const ignored = read(".gitignore")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .includes("package-lock.json");
  assert.equal(ignored, false, ".gitignore still excludes package-lock.json");

  const lock = JSON.parse(read("package-lock.json"));
  const pkg = JSON.parse(read("package.json"));
  assert.deepEqual(
    lock.packages[""].dependencies,
    pkg.dependencies,
    "package-lock.json root dependencies differ from package.json -- run npm install",
  );
  const noIntegrity = Object.entries(lock.packages)
    .filter(([k, p]) => k && !p.link && !p.integrity)
    .map(([k]) => k);
  assert.deepEqual(noIntegrity, [], "lockfile entries without an integrity hash");
});

test("CI installs node dependencies with npm ci, never npm install", () => {
  const blocks = workflowFiles.flatMap(runBlocks);
  const loose = blocks.filter((b) => /\bnpm\s+(install|i)\b/.test(b.body));
  assert.deepEqual(
    loose.map((b) => `${b.file}:${b.line}`),
    [],
    "npm install ignores a stale lock silently; use npm ci",
  );
  assert.ok(blocks.some((b) => /\bnpm\s+ci\b/.test(b.body)), "no npm ci step found");
});

// ── least privilege: security-events: write only where SARIF is uploaded ────
// The dogfood job asked for security-events: write while calling the action
// with upload-sarif: 'false' -- a write token for the Security tab that no
// step used. A grant nothing needs is still a grant a compromised step gets.
/**
 * YAML text with comments removed: whole-line `#` comments and ` # ...` tails.
 * The grant is a key, not a phrase -- a comment that *explains* why a job has
 * no security-events: write must not read as the grant itself.
 */
const stripComments = (text) =>
  text
    .split(/\r?\n/)
    .filter((l) => !/^\s*#/.test(l))
    .map((l) => l.replace(/\s+#\s.*$/, ""))
    .join("\n");

/** Jobs of a workflow as { name, text }. Understands two-space job keys under `jobs:`. */
function jobs(rel) {
  const text = stripComments(read(rel));
  const body = text.slice(text.search(/^jobs:\s*$/m));
  const parts = body.split(/^ {2}(?=[\w-]+:\s*$)/m).slice(1);
  return parts.map((p) => ({ name: p.slice(0, p.indexOf(":")), text: p }));
}

test("sanity: the job reader sees every job in ci.yml", () => {
  const names = jobs(".github/workflows/ci.yml").map((j) => j.name);
  assert.ok(names.length >= 3, `expected >= 3 jobs in ci.yml, saw ${names}`);
});

test("only jobs that upload SARIF request security-events: write", () => {
  const offenders = [];
  for (const wf of workflowFiles) {
    const text = stripComments(read(wf));
    const head = text.slice(0, text.search(/^jobs:\s*$/m));
    const workflowWide = /security-events:\s*write/.test(head);
    for (const j of jobs(wf)) {
      const asks = workflowWide || /security-events:\s*write/.test(j.text);
      if (!asks) continue;
      const uploads =
        j.text.includes("github/codeql-action/") ||
        (/uses:\s*\.\/\s*$/m.test(j.text) && !/upload-sarif:\s*'?"?false/.test(j.text));
      if (!uploads) offenders.push(`${wf} job ${j.name}`);
    }
  }
  assert.deepEqual(offenders, [], "security-events: write granted to a job that uploads nothing");
});
