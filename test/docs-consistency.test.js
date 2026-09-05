// Documentation must agree with the code. This test exists because it did not.
//
// Scenario S7 shipped in PR #27 with the source, the PoC, the rules and the
// main README updated -- and challenges/README.md, SECURITY.md, CONTRIBUTING.md,
// the issue templates and every challenge's Setup command left behind. The
// Setup omission was not cosmetic: each challenge pins the *other* scenarios to
// "fixed" so its own mission has exactly one answer, and every one of them
// still pinned six instead of seven, leaving S7 live and the mission ambiguous.
//
// Counting by hand is what failed. So these assertions derive the numbers from
// the code -- the LAB_S* toggles the server actually reads, the tools actually
// registered, the rules actually declared -- and check the docs against them.
// Add S8 and this test tells you every file you forgot.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => readFileSync(join(root, rel), "utf8");

// ── ground truth, derived from source ──────────────────────────────────────
const serverSrc = read("src/server.js");
const toolsSrc = read("src/tools.js");

/** Scenario ids the server actually wires: s1..sN in the modes object. */
const scenarios = [...serverSrc.matchAll(/^\s*s(\d+):\s*fixed\(/gm)].map((m) =>
  Number(m[1]),
);
const scenarioCount = scenarios.length;
/** Every LAB_S* toggle a fully-hardened run must set. */
const toggles = scenarios.map((n) => `LAB_S${n}`);

test("sanity: the server wires a contiguous s1..sN", () => {
  assert.ok(scenarioCount >= 6, "expected at least the six original scenarios");
  assert.deepEqual(
    scenarios,
    Array.from({ length: scenarioCount }, (_, i) => i + 1),
    "scenario ids are not contiguous s1..sN — update this test deliberately",
  );
});

// ── every challenge isolates its own scenario ──────────────────────────────
// This is the assertion that would have caught the S7 miss.
test("each challenge's Setup pins every OTHER scenario to fixed", () => {
  const files = readdirSync(join(root, "challenges"))
    .filter((f) => /^s\d+\.md$/.test(f))
    .sort();

  assert.equal(
    files.length,
    scenarioCount,
    `challenges/ has ${files.length} scenario files but the server wires ${scenarioCount}`,
  );

  for (const file of files) {
    const n = Number(file.match(/^s(\d+)\.md$/)[1]);
    const setup = read(`challenges/${file}`)
      .split("\n")
      .find((l) => /^LAB_.*node src\/(http-)?server\.js/.test(l));

    assert.ok(setup, `${file}: no Setup command line found`);

    // S1's toggle is spelled LAB_MODE in its own Setup; the rest use LAB_S<n>.
    const own = n === 1 ? /LAB_(MODE|S1)=vuln/ : new RegExp(`LAB_S${n}=vuln`);
    assert.match(setup, own, `${file}: does not set its own scenario to vuln`);

    for (const t of toggles) {
      if (t === `LAB_S${n}`) continue;
      assert.ok(
        setup.includes(`${t}=fixed`),
        `${file}: Setup does not pin ${t}=fixed — that scenario stays vulnerable ` +
          `and this challenge has more than one answer`,
      );
    }
  }
});

// ── the "run everything hardened" commands cover every toggle ───────────────
test("README's all-fixed commands set every LAB_S* toggle", () => {
  const readme = read("README.md");
  const allFixed = readme
    .split("\n")
    .filter((l) => l.includes("=fixed") && l.includes("npm start"));

  assert.ok(allFixed.length >= 1, "no all-fixed command found in README");

  for (const line of allFixed) {
    for (const t of toggles) {
      assert.ok(
        line.includes(t),
        `README all-fixed command omits ${t}: ${line.slice(0, 70)}…`,
      );
    }
  }
});

// ── the PoC hardens every scenario too ─────────────────────────────────────
test("the PoC's ALL_FIXED build covers every scenario", () => {
  const poc = read("poc/exploit.js");
  const block = poc.slice(poc.indexOf("ALL_FIXED"), poc.indexOf("ALL_FIXED") + 400);
  for (const t of toggles) {
    assert.ok(block.includes(t), `poc ALL_FIXED omits ${t}`);
  }
});

// ── docs list every scenario ───────────────────────────────────────────────
test("both scenario tables list every scenario", () => {
  for (const rel of ["README.md", "challenges/README.md"]) {
    const text = read(rel);
    for (const n of scenarios) {
      assert.match(
        text,
        new RegExp(`\\bS${n}\\b`),
        `${rel} never mentions S${n}`,
      );
    }
  }
});

test("challenges/README table has a row per challenge file", () => {
  const table = read("challenges/README.md");
  for (const n of scenarios) {
    assert.ok(
      table.includes(`[s${n}.md](s${n}.md)`),
      `challenges/README.md has no table row linking s${n}.md`,
    );
  }
});

// ── tool + rule counts stated in prose match reality ───────────────────────
test("stated tool count matches the tools actually registered", () => {
  const registered = (toolsSrc.match(/server\.registerTool\(/g) ?? []).length;
  const words = {
    6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
    11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
    15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
  };
  const readme = read("README.md");
  const claim = readme.match(/exposing (\w+) MCP tools/);
  assert.ok(claim, "README no longer states a tool count — update this test");
  assert.equal(
    claim[1].toLowerCase(),
    words[registered],
    `README says "${claim[1]} MCP tools" but src/tools.js registers ${registered}`,
  );
});

test("detection README lists every rule id in the ruleset", () => {
  const rules = readdirSync(join(root, "detection/semgrep"))
    .filter((f) => f.endsWith(".yml"))
    // `^\s+` demanded at least one leading whitespace character, but several
    // language packs put `- id:` at column 0 -- and in JavaScript `\s` matches
    // a newline, so those ids matched only by accident, when a blank line
    // happened to precede them. Measured 2026-09-05: this saw 21 of 46 rules;
    // the other 25 were never checked against the docs at all. `[ 	]*` cannot
    // cross a line boundary, so it is column-agnostic without being accidental.
    .flatMap((f) => [...read(`detection/semgrep/${f}`).matchAll(/^[ \t]*- id:\s*(\S+)/gm)])
    .map((m) => m[1]);
  const doc = read("detection/README.md");

  assert.ok(rules.length >= 6, "expected at least six rules");
  for (const id of rules) {
    assert.ok(doc.includes(id), `detection/README.md never mentions rule ${id}`);
  }

  // The prose count is a claim like any other, and it drifted: the table
  // listed all 46 while the sentence above it still said 40, because nothing
  // held it. It is held now.
  const claim = doc.match(/\*\*(\d+) rules across the `detection\/semgrep\/` directory\*\*/);
  assert.ok(claim, "detection/README.md no longer states a rule count in the expected form");
  assert.strictEqual(
    Number(claim[1]),
    rules.length,
    `detection/README.md says ${claim[1]} rules, the directory declares ${rules.length}`,
  );

  // The root README repeats the same number; a reader hits that one first.
  const root_claim = read("README.md").match(/ships (\d+) \[Semgrep\]/);
  assert.ok(root_claim, "README.md no longer states the rule count in the expected form");
  assert.strictEqual(
    Number(root_claim[1]),
    rules.length,
    `README.md says ${root_claim[1]} rules, the directory declares ${rules.length}`,
  );
});

// ── SECURITY.md's toggle range covers every scenario ───────────────────────
test("SECURITY.md's toggle range ends at the last scenario", () => {
  const sec = read("SECURITY.md");
  const last = `LAB_S${scenarioCount}`;
  assert.ok(
    sec.includes(last),
    `SECURITY.md describes the toggles but never reaches ${last}`,
  );
});

// ── repeated numeric claims in the prose must agree with each other ─────────
// v3.10's mega-PR updated the PoC output BLOCK (38 rows, S1-S13) but left
// "28-row" and "34/34 rows" in the surrounding prose, and "42 tests" in the
// file-table row while the Quickstart said "51 tests". The table-derived
// asserts above all passed — those numbers live in free text, not the tables.
// A count stated more than once must state the SAME number every time. This is
// the class the whole v3.10 doc-drift belonged to; it derives nothing from
// source, it just refuses to let README contradict itself.
test("README states each repeated count consistently", () => {
  const readme = read("README.md");
  const nums = (re) => [
    ...new Set([...readme.matchAll(re)].map((m) => Number(m[1]))),
  ];

  const pocRows = nums(/(\d+)[- ]row\b/gi).concat(
    [...readme.matchAll(/(\d+)\/\d+ rows\b/gi)].map((m) => Number(m[1])),
  );
  assert.ok(
    new Set(pocRows).size <= 1,
    `README states inconsistent PoC-row counts ${[...new Set(pocRows)]} — ` +
      `update every "N-row" / "N/N rows" mention together`,
  );

  const testCounts = nums(/(\d+) tests?\b/gi);
  assert.ok(
    testCounts.length <= 1,
    `README states inconsistent unit-test counts ${testCounts} — ` +
      `the Quickstart and the file table must agree`,
  );
});
