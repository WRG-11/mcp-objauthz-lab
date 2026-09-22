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

// ── CITATION.cff is a published claim too ───────────────────────────────────
// Nothing held it, and it drifted twice over: `version: 3.12.1` after the
// 3.12.2 release, and an abstract still saying "seven planted flaws" and
// "eight of its twelve rules" while the lab wired thirteen scenarios. A
// citation is copied into papers verbatim; it gets the same treatment as the
// README. Numbers are derived from source, the prose is checked against them.
const numberWords = {
  1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven",
  8: "eight", 9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
  14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
  19: "nineteen", 20: "twenty",
};

/** Languages per rule id, for both `languages: [a, b]` and block-list forms. */
function ruleLanguages() {
  const byId = new Map();
  for (const f of readdirSync(join(root, "detection/semgrep")).filter((x) => x.endsWith(".yml"))) {
    const blocks = read(`detection/semgrep/${f}`).split(/^[ \t]*- id:[ \t]*/m).slice(1);
    for (const b of blocks) {
      const id = b.split(/\s/)[0];
      const inline = b.match(/languages:[ \t]*\[([^\]]*)\]/);
      const list = b.match(/languages:[ \t]*\r?\n((?:[ \t]*- [\w-]+[ \t]*\r?\n)+)/);
      const langs = inline
        ? inline[1].split(",").map((s) => s.trim())
        : list
          ? [...list[1].matchAll(/- ([\w-]+)/g)].map((m) => m[1])
          : [];
      byId.set(id, new Set([...(byId.get(id) ?? []), ...langs]));
    }
  }
  return byId;
}

test("sanity: the rule-language reader sees languages for every rule", () => {
  const byId = ruleLanguages();
  assert.ok(byId.size >= 6, "expected at least six rules");
  const empty = [...byId].filter(([, l]) => l.size === 0).map(([id]) => id);
  assert.deepEqual(empty, [], "rules whose languages the reader could not parse");
});

test("CITATION.cff version matches package.json", () => {
  const cff = read("CITATION.cff").match(/^version:\s*"?([\d.]+)"?\s*$/m);
  assert.ok(cff, "CITATION.cff has no version: line");
  assert.equal(cff[1], JSON.parse(read("package.json")).version);
});

test("CITATION.cff abstract states the scenario and language counts the code has", () => {
  const cff = read("CITATION.cff").replace(/\s+/g, " ");
  const byId = ruleLanguages();
  const python = [...byId.values()].filter((l) => l.has("python")).length;
  const langs = new Set([...byId.values()].flatMap((l) => [...l]));
  const further = [...langs].filter((l) => !["javascript", "typescript", "python"].includes(l)).length;

  const flaws = cff.match(/carrying (\w+) planted/i);
  assert.ok(flaws, "abstract no longer says 'carrying N planted' -- update this test");
  assert.equal(flaws[1].toLowerCase(), numberWords[scenarioCount], "planted-flaw count");

  const py = cff.match(/(\w+) of its rules target Python/i);
  assert.ok(py, "abstract no longer says 'N of its rules target Python' -- update this test");
  assert.equal(py[1].toLowerCase(), numberWords[python], "Python rule count");

  const more = cff.match(/(\w+) further languages/i);
  assert.ok(more, "abstract no longer says 'N further languages' -- update this test");
  assert.equal(more[1].toLowerCase(), numberWords[further], "further-language count");
});

// ── the README's test count is the suite's, not a remembered number ────────
// "npm test # 52 tests" stayed true only for the three files it was written
// about; the suite grew security-hardening, ci-hardening and the PoC-output
// check, and `npm test` ran more than the README said. The consistency check
// above only refuses two DIFFERENT numbers -- one stale number passes it.
test("README's unit-test count equals the tests in test/", () => {
  const count = readdirSync(join(root, "test"))
    .filter((f) => f.endsWith(".test.js"))
    .reduce((n, f) => n + (read(`test/${f}`).match(/^test\(/gm) ?? []).length, 0);
  const claim = read("README.md").match(/npm test\s+#\s*(\d+) tests\b/);
  assert.ok(claim, "README no longer states `npm test  # N tests` -- update this test");
  assert.equal(Number(claim[1]), count, `README says ${claim[1]} tests, test/ declares ${count}`);
});

// ── every scenario has its own README section ──────────────────────────────
test("README has a Scenario section for every scenario", () => {
  const readme = read("README.md");
  const missing = scenarios.filter((n) => !new RegExp(`^## Scenario S${n} `, "m").test(readme));
  assert.deepEqual(missing.map((n) => `S${n}`), [], "README has no '## Scenario S<n>' section for");
});

// ── the host config in challenges/README sets every toggle ─────────────────
test("challenges/README's MCP host config lists every scenario toggle", () => {
  const env = read("challenges/README.md").match(/"env":\s*\{([^}]*)\}/);
  assert.ok(env, "challenges/README.md no longer has an MCP host env block");
  for (const t of toggles) {
    const key = t === "LAB_S1" ? /"LAB_(MODE|S1)"/ : new RegExp(`"${t}"`);
    assert.match(env[1], key, `host config env omits ${t}`);
  }
});
