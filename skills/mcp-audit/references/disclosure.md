# Reporting findings on a server you do not maintain

On your own server, open a pull request for whatever the audit found. On someone
else's server, the severity of each finding ([`SEVERITY.md`](../SEVERITY.md))
decides the channel. Check the project's `SECURITY.md` first: when it names a
channel, use that one.

## Channel per severity

| Severity | Channel | Window |
|---|---|---|
| Critical | Private security advisory on the upstream repository (the "Report a vulnerability" button under Security), or the channel `SECURITY.md` names | Ask for a fix within 7 days; follow up through the published contact if there is no reply in 72 hours |
| High | Private security advisory | 30 days for a fix; public on the fix release or on day 90, whichever comes first |
| Medium | Private notice (advisory, or email if an advisory is heavier than the issue) with the suggested fix and a written deadline | Public after 90 days whether or not it is fixed; earlier on the fix release |
| Low | Public issue, or a public pull request when the fix is clear and small | None |
| Info | One public issue or pull request per repository, all Info findings batched | None |

Do not post Critical, High or Medium findings anywhere public - issues, pull
requests, commit messages, chat - before the window closes. That includes the
audit report itself: keep it private until then.

## Edge cases

| Situation | What to do |
|---|---|
| The maintainer asks for another channel | Use it, and note the switch in the report. |
| No reachable maintainer (no `SECURITY.md`, no contact, issues closed) | Use a private advisory anyway. For a Critical finding in an abandoned package, report it to the package registry's security team. |
| Mixed severities in one repository | Report the highest first through its channel. The rest can go public together once that window closes. |
| The disclosure is the patch | Some Medium findings (an untested mutation tool, mixed error idioms, a non-atomic write) are fully explained by a small fix the maintainer can judge from the diff, with no exploit to withhold. Send those as a public pull request and record `OVERRIDE: de-escalated to Low - the disclosure is the patch`. |
| Already tracked upstream | When an open issue tracks the same problem and the README documents the limitation, comment on that issue instead of filing a new report, and record `OVERRIDE: de-escalated to Low - tracked in #<n> and documented`. |
| A cross-tenant finding (`AUTHZ-*`) with a trivial reproduction | Still High, still private: a public proof of concept against a deployed multi-tenant server is a live exploit. |

## What a report contains

- the affected package, version and commit;
- the tool or resource, and the finding id with its severity;
- a reproduction a maintainer can run locally, using test tenants you created,
  never real users' data;
- the impact in one or two sentences;
- a suggested fix;
- the disclosure window you are offering.
