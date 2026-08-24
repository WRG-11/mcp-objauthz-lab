// Real-capture fixture for rule: mcp-wildcard-sentinel-scope-bypass
//
// From audit: Jira wiki markup rendering and command-palette UI filters use
// "*" and "all" as TEXTUAL values, not as authorization scope decisions.
// The hardened rule must NOT fire on these patterns — they're the SILENT
// half of the two-way canary.
//
// SILENT: wildcard/"all" in textual context (markup, UI filter), not authz.

function renderWikiMarkup(text) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  // Jira-style wiki markup: *bold* -> <b>bold</b>
  return text.replace(/\*(.+?)\*/g, "<b>$1</b>");
}

function renderItalicMarkup(text) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  // _italic_ -> <i>italic</i>
  return text.replace(/_(.+?)_/g, "<i>$1</i>");
}

function commandPaletteFilter(items, scope) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  // UI command palette: scope === "all" means "show all items", not authz bypass
  if (scope === "all") {
    return items;
  }
  return items.filter((item) => item.scope === scope);
}

function searchFilterResults(results, query) {
  // ok: mcp-wildcard-sentinel-scope-bypass
  // Search filter: query === "*" means "match all", not authz decision
  if (query === "*") {
    return results;
  }
  return results.filter((r) => r.name.includes(query));
}