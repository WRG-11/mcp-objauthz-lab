// Unit tests for detection/check-annotations.js: the per-annotation fixture
// check. The finding-count assertion in ci.yml cannot tell a rule that fires
// on the wrong line, or never fires at all, from a working one -- its `want`
// is set to whatever fires. This check reads every `ruleid:` / `ok:` marker
// and asks whether the marked line behaves as marked.

import test from "node:test";
import assert from "node:assert/strict";
import { parseAnnotations, evaluate, compareToBaseline } from "../detection/check-annotations.js";

const SRC = [
  "function a() {",               // 1
  "  // ruleid: rule-x",          // 2
  "  // a second comment line",   // 3
  "",                             // 4
  "  return store.get(id);",      // 5  <- marked by line 2
  "}",                            // 6
  "# ok: rule-x, rule-y",         // 7
  "safe_call()",                  // 8  <- marked by line 7
].join("\n");

test("a marker points at the next line that is neither a comment nor blank", () => {
  const anns = parseAnnotations(SRC);
  assert.deepEqual(anns, [
    { kind: "ruleid", rule: "rule-x", line: 5, text: "return store.get(id);" },
    { kind: "ok", rule: "rule-x", line: 8, text: "safe_call()" },
    { kind: "ok", rule: "rule-y", line: 8, text: "safe_call()" },
  ]);
});

test("todoruleid and todook markers are not expectations", () => {
  assert.deepEqual(parseAnnotations("// todoruleid: rule-x\ncall()\n# todook: rule-x\nother()"), []);
});

const ANN = { file: "a.js", kind: "ruleid", rule: "rule-x", line: 5, text: "return store.get(id);" };
const OK = { file: "a.js", kind: "ok", rule: "rule-x", line: 8, text: "safe_call()" };
const hit = (rule, start, end) => ({ file: "a.js", rule, start, end });

test("a finding whose span covers the marked line satisfies ruleid", () => {
  const r = evaluate([ANN], [hit("rule-x", 1, 6)]);
  assert.deepEqual(r.missed, []);
});

test("a finding that ends before the marked line does not satisfy ruleid", () => {
  const r = evaluate([ANN], [hit("rule-x", 1, 4)]);
  assert.equal(r.missed.length, 1);
});

test("a finding that starts after the marked line does not satisfy ruleid", () => {
  const r = evaluate([ANN], [hit("rule-x", 6, 7)]);
  assert.equal(r.missed.length, 1);
});

test("a covering finding of another rule does not satisfy ruleid", () => {
  const r = evaluate([ANN], [hit("rule-y", 5, 5)]);
  assert.equal(r.missed.length, 1);
});

test("a covering finding in another file does not satisfy ruleid", () => {
  const r = evaluate([ANN], [{ file: "b.js", rule: "rule-x", start: 5, end: 5 }]);
  assert.equal(r.missed.length, 1);
});

test("ok is violated when its rule covers the marked line, and only then", () => {
  assert.equal(evaluate([OK], [hit("rule-x", 8, 8)]).okFired.length, 1);
  assert.equal(evaluate([OK], [hit("rule-y", 8, 8)]).okFired.length, 0);
  assert.equal(evaluate([OK], [hit("rule-x", 9, 9)]).okFired.length, 0);
});

test("baseline: a new miss fails, a listed miss passes", () => {
  const { missed } = evaluate([ANN], []);
  assert.equal(compareToBaseline({ missed, okFired: [] }, { missed: [], okFired: [] }).failed, true);
  const key = missed[0].key;
  const res = compareToBaseline({ missed, okFired: [] }, { missed: [key], okFired: [] });
  assert.equal(res.failed, false);
});

test("baseline: an entry that no longer fails is stale and fails, so the baseline only shrinks on purpose", () => {
  const res = compareToBaseline({ missed: [], okFired: [] }, { missed: ["a.js|rule-x|return store.get(id);"], okFired: [] });
  assert.equal(res.failed, true);
  assert.deepEqual(res.stale.missed, ["a.js|rule-x|return store.get(id);"]);
});

test("baseline: a newly firing ok fails", () => {
  const { okFired } = evaluate([OK], [hit("rule-x", 8, 8)]);
  const res = compareToBaseline({ missed: [], okFired }, { missed: [], okFired: [] });
  assert.equal(res.failed, true);
  assert.equal(res.added.okFired.length, 1);
});

test("the key is the marked line's text, so an unrelated edit above it does not churn the baseline", () => {
  const moved = { ...ANN, line: 40 };
  assert.equal(evaluate([moved], []).missed[0].key, evaluate([ANN], []).missed[0].key);
});

test("two identical marked lines count twice: fixing one of them is visible", () => {
  const twin = { ...ANN, line: 9 };
  const { missed } = evaluate([ANN, twin], [hit("rule-x", 9, 9)]);
  assert.equal(missed.length, 1);
  const key = missed[0].key;
  const res = compareToBaseline({ missed, okFired: [] }, { missed: [key, key], okFired: [] });
  assert.equal(res.failed, true);
  assert.deepEqual(res.stale.missed, [key]);
});
