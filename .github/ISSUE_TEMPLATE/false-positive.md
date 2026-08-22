---
name: False positive — a rule fired on correct code
about: A detection rule flagged code that is properly authorized
title: "[FP] <rule-id> fires on "
labels: ["false-positive", "detection"]
---

<!--
This is treated as a real defect, not noise. A gate wider than the defect it
targets gets switched off, and a switched-off rule protects nothing.
-->

**Rule id**
<!-- e.g. mcp-wildcard-sentinel-scope-bypass -->

**Language**
<!-- javascript / typescript / python -->

**Minimal snippet that triggers it**

```
paste the smallest code that still produces the finding
```

**Why this code is actually safe**
<!-- Which check authorizes it, and where? If the authorization happens in a
     helper the rule cannot see, say so — that is useful information. -->

**Semgrep version**
<!-- semgrep --version -->
