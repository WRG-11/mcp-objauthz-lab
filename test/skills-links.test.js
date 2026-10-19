// A skill under skills/ is installed by copying its folder somewhere else
// (~/.claude/skills/<name>/ or a project's .claude/skills/). A relative link that
// climbs out of that folder works in this repository and breaks after the copy,
// so links that leave the skill must be absolute URLs. This test checks both
// halves: every relative link resolves to a file, and none leaves its skill.

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, resolve, sep } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const skillsDir = join(root, "skills");

function markdownFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return markdownFiles(full);
    return name.endsWith(".md") ? [full] : [];
  });
}

/** Relative link targets in a Markdown file, code spans and fences removed. */
function relativeLinks(text) {
  const prose = text.replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "");
  return [...prose.matchAll(/\]\(([^)\s]+)\)/g)]
    .map((m) => m[1])
    .filter((href) => !/^[a-z][a-z0-9+.-]*:/i.test(href) && !href.startsWith("#"))
    .map((href) => href.split("#")[0]);
}

const skills = readdirSync(skillsDir).filter((name) =>
  statSync(join(skillsDir, name)).isDirectory(),
);

test("skills/ holds at least one skill with a SKILL.md", () => {
  assert.ok(skills.length >= 1, "no skill folders under skills/");
  for (const name of skills) {
    const skillMd = join(skillsDir, name, "SKILL.md");
    assert.ok(existsSync(skillMd), `skills/${name} has no SKILL.md`);
    assert.ok(
      readFileSync(skillMd, "utf8").startsWith("---"),
      `skills/${name}/SKILL.md must open with frontmatter on its first line`,
    );
  }
});

test("relative links in a skill resolve and stay inside that skill", () => {
  const broken = [];
  const escaping = [];
  let checked = 0;
  for (const name of skills) {
    const skillRoot = join(skillsDir, name);
    for (const file of markdownFiles(skillRoot)) {
      const text = readFileSync(file, "utf8");
      for (const href of relativeLinks(text)) {
        if (href === "") continue;
        checked += 1;
        const target = resolve(dirname(file), href);
        const label = `${relative(root, file)} -> ${href}`;
        if (!existsSync(target)) broken.push(label);
        if (target !== skillRoot && !target.startsWith(skillRoot + sep)) escaping.push(label);
      }
    }
  }
  // A link parser that matches nothing would pass both checks below.
  assert.ok(checked >= 1, "no relative links found -- the link pattern no longer matches");
  assert.deepEqual(broken, [], "relative links that point at no file");
  assert.deepEqual(escaping, [], "relative links that leave the skill folder (use an absolute URL)");
});
