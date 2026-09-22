// The README's "Expected `npm run poc` output" block is a claim about what a
// command prints. It was edited by hand as scenarios were added, never read
// back from the command, and it drifted: it showed 40 rows under a "38/38"
// footer -- two S11 X-Forwarded-For rows the PoC no longer runs -- and "14
// cross-tenant routes" where the hardened arm tries 13. Every table-derived
// check in docs-consistency.test.js passed, because none of them ran the PoC.
//
// This one does. It is the slowest test in the suite (it spawns every
// scenario's server, ~10 s) and it is the only one that can catch this class.
// To refresh the block after a deliberate PoC change: run `npm run --silent poc`
// and paste its output between the fences.

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Lines with trailing whitespace dropped and leading/trailing blank lines trimmed. */
const normalise = (text) => {
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\s+$/, ""));
  while (lines.length && lines[0] === "") lines.shift();
  while (lines.length && lines.at(-1) === "") lines.pop();
  return lines;
};

test("README's expected PoC output is what the PoC prints", { timeout: 180_000 }, () => {
  const readme = readFileSync(join(root, "README.md"), "utf8");
  const block = readme.match(/Expected `npm run poc` output[^\n]*(?:\r?\n)+```\r?\n([\s\S]*?)```/);
  assert.ok(block, "README no longer has the 'Expected `npm run poc` output' block -- update this test");

  const actual = execFileSync(process.execPath, [join(root, "poc", "exploit.js")], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });

  const want = normalise(block[1]);
  const got = normalise(actual);
  assert.ok(got.length > 10, "the PoC printed almost nothing -- it did not run, which is not a match");
  assert.deepEqual(got, want, "README's PoC block differs from `npm run --silent poc` output");
});
