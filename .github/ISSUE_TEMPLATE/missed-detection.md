---
name: Missed detection — a real bug the rules walked past
about: An authorization flaw in MCP server code that no rule flags
title: "[MISS] "
labels: ["missed-detection", "detection"]
---

<!--
The rules currently catch 7 of the 9 scenarios against this lab's own source.
detection/README.md explains why. A miss is a starting point, not something to
argue with.
-->

**Minimal vulnerable snippet**

```
the smallest handler that carries the flaw and produces no finding
```

**Language**
<!-- javascript / typescript / python -->

**What the attacker gets**
<!-- Which object does an unauthorized caller reach, and how? -->

**Is this a new shape or a known one?**
<!-- If it looks like one of the nine scenarios (see README), say which. If the
     shape is new, that is more interesting — describe what makes it different
     from a rule's existing pattern. -->
