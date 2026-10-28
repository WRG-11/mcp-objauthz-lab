// Per-annotation check of the detection fixtures.
//
// The finding-count assertion in ci.yml answers "did the total change?". It
// cannot answer "does each rule fire where its fixture says it does?": `want`
// is set to whatever fires, so a rule that never fires on its own positive
// fixture keeps CI green. Measured 2026-10-28: 13 of 45 rules fired nowhere in
// their fixtures and 70 of 136 `ruleid:` markers were not covered by any
// finding, all under a passing count check. `semgrep --test` would catch this,
// but it pairs `<rules>.yml` with a same-named target file, and this repo keeps
// scenario-named fixtures instead (see detection/README.md).
//
// What this checks: every `ruleid: R` marker must have a finding of R whose
// line span covers the marked line (the next line that is neither a comment
// nor blank), and no `ok: R` marked line may be covered by a finding of R.
// What it does not check: whether a finding is right for the right reason,
// and findings on lines that carry no marker (the count assertion still
// covers those).
//
// Known failures live in detection/fixture-annotation-baseline.json. A new
// failure fails CI; so does a baseline entry that no longer fails, so the
// baseline shrinks only when someone removes the entry on purpose.
//
// Usage: node detection/check-annotations.js <semgrep.json> <fixtures-dir> <baseline.json>

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MARKER = /(?:#|\/\/|--|\/\*)\s*(todoruleid|todook|ruleid|ok):\s*([\w,\s-]+?)\s*(?:\*\/)?\s*$/;
const COMMENT = /^\s*(#|\/\/|--|\/\*|\*)/;

function parseAnnotations(text) {
  const lines = text.split(/\r?\n/);
  const out = [];
  lines.forEach((ln, i) => {
    const m = MARKER.exec(ln);
    if (!m || m[1].startsWith("todo")) return;
    let j = i + 1;
    while (j < lines.length && (COMMENT.test(lines[j]) || !lines[j].trim())) j += 1;
    const text = j < lines.length ? lines[j].trim() : "";
    for (const rule of m[2].split(",").map((r) => r.trim()).filter(Boolean)) {
      out.push({ kind: m[1], rule, line: j + 1, text });
    }
  });
  return out;
}

function keyOf(a) {
  return `${a.file}|${a.rule}|${a.text}`;
}

function evaluate(annotations, findings) {
  const covers = (a) => findings.some((f) => f.file === a.file && f.rule === a.rule && f.start <= a.line && a.line <= f.end);
  const missed = [];
  const okFired = [];
  for (const a of annotations) {
    const hit = covers(a);
    if (a.kind === "ruleid" && !hit) missed.push({ ...a, key: keyOf(a) });
    if (a.kind === "ok" && hit) okFired.push({ ...a, key: keyOf(a) });
  }
  return { missed, okFired };
}

// Multiset difference: each baseline entry absorbs one failure with that key.
function diff(actualKeys, baselineKeys) {
  const left = new Map();
  for (const k of baselineKeys) left.set(k, (left.get(k) || 0) + 1);
  const added = [];
  for (const k of actualKeys) {
    if (left.get(k)) left.set(k, left.get(k) - 1);
    else added.push(k);
  }
  const stale = [];
  for (const [k, n] of left) for (let i = 0; i < n; i += 1) stale.push(k);
  return { added, stale };
}

function compareToBaseline(result, baseline) {
  const m = diff(result.missed.map((r) => r.key), baseline.missed || []);
  const o = diff(result.okFired.map((r) => r.key), baseline.okFired || []);
  const added = {
    missed: result.missed.filter((r) => m.added.includes(r.key)),
    okFired: result.okFired.filter((r) => o.added.includes(r.key)),
  };
  const stale = { missed: m.stale, okFired: o.stale };
  const failed = m.added.length + o.added.length + m.stale.length + o.stale.length > 0;
  return { failed, added, stale };
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    return e.isDirectory() ? walk(p) : [p];
  });
}

function main(argv) {
  const [jsonPath, fixturesDir, baselinePath] = argv;
  if (!jsonPath || !fixturesDir || !baselinePath) {
    console.error("usage: node detection/check-annotations.js <semgrep.json> <fixtures-dir> <baseline.json>");
    return 2;
  }
  const root = path.resolve(fixturesDir);
  const rel = (p) => path.relative(root, path.resolve(p)).split(path.sep).join("/");
  const annotations = walk(root).flatMap((f) =>
    parseAnnotations(fs.readFileSync(f, "utf8")).map((a) => ({ ...a, file: rel(f) })));
  const data = JSON.parse(fs.readFileSync(jsonPath, "utf8"));
  const findings = data.results.map((r) => ({
    file: rel(r.path),
    rule: r.check_id.split(".").pop(),
    start: r.start.line,
    end: r.end.line,
  }));
  const baseline = JSON.parse(fs.readFileSync(baselinePath, "utf8"));
  const result = evaluate(annotations, findings);
  const cmp = compareToBaseline(result, baseline);
  const nRuleid = annotations.filter((a) => a.kind === "ruleid").length;
  const nOk = annotations.length - nRuleid;
  console.log(`fixture annotations: ${nRuleid} ruleid, ${nOk} ok; ` +
    `${result.missed.length} ruleid not covered, ${result.okFired.length} ok covered ` +
    `(baseline ${(baseline.missed || []).length} + ${(baseline.okFired || []).length})`);
  for (const r of cmp.added.missed) console.error(`NEW miss: ${r.file}:${r.line} ruleid ${r.rule} does not fire`);
  for (const r of cmp.added.okFired) console.error(`NEW ok fired: ${r.file}:${r.line} ${r.rule} fires on an ok line`);
  for (const k of cmp.stale.missed) console.error(`FIXED, remove from baseline.missed: ${k}`);
  for (const k of cmp.stale.okFired) console.error(`FIXED, remove from baseline.okFired: ${k}`);
  return cmp.failed ? 1 : 0;
}

export { parseAnnotations, evaluate, compareToBaseline };

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
