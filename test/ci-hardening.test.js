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
