# Detection lifecycle

```
draft ──────────► experimental ──────────► stable ──────────► deprecated
  │                    │                      │                   │
  not built            built, on a soak       production          kept for history,
  anywhere             window with an         reviewed on         never built
                       owner and a deadline   change
```

Status is metadata with consequences: the build stage renders `experimental` and
`stable` only.

## `draft`

Work in progress. Committed so it is visible and reviewable, built nowhere.
Analyst context is warned about rather than required, so a rule can be shared
before it is finished.

Use it when the logic is still moving, or when the data source it needs is not
onboarded yet.

## `experimental`

Deployed, on a clock.

```yaml
status: "experimental"
lifecycle:
  soak_started: "2026-08-12"
  soak_days: 21
  owner: "huseyn.aghazada"
```

Validation requires `soak_started` for an experimental rule, because a soak
window with no start can never end — which is how rules spend a year "on trial"
while quietly generating alerts nobody trusts.

During the soak, watch the alert volume, the true-positive rate, and what triage
actually had to do. Tune in the environment, not in the rule.

`pipelines.tools.soak_report` lists what is due, and the weekly health workflow
fails once a window closes without a decision:

```
$ python -m pipelines.tools.soak_report
1 rule(s) in a soak window:

  WEB-WAF-001  4d left    started 2026-08-12 (17/21 days, owner: huseyn.aghazada)
```

When the window closes there are exactly three options: promote, extend with a
reason, or retire. "Leave it and see" is not one of them.

## `stable`

Production. The quality gates escalate from warning to error here:
`false_positives`, `triage`, `references`, and `risk` become required. Promoting
a rule is therefore a claim that it has met real data and that someone knows what
to do when it fires.

Bump `version` and `modified` on every change:

| Change | Version |
|--------|---------|
| Typo, comment, reference | patch — `1.0.0` → `1.0.1` |
| Threshold, added exclusion, new platform block | minor — `1.0.0` → `1.1.0` |
| Logic change that alters what the rule detects | major — `1.0.0` → `2.0.0` |

A major bump means the alert now means something different from what it meant
before. Historical alerts for that rule are no longer comparable, which is worth
saying out loud in the pull request.

## `deprecated`

Retired, kept for history.

```yaml
status: "deprecated"
status_reason: "Superseded by ID-AD-014, which covers the same behaviour without the RC4 dependency."
```

Never delete a rule file and never reuse its ID. The ID appears in alert history,
incident records, and exception tickets; deleting the file makes those references
dangle. `status_reason` is what stops someone re-implementing the rule two years
later without knowing why it went away.

## Tuning

Tuning is an environment change, not a rule change. It lives in
`environments/<env>/exclusions.yaml` and it needs a comment.

Scope as narrowly as the false positive allows:

```
a specific parent process  ›  a specific host  ›  a subnet  ›  an account type
```

Each step outward is a larger blind spot. And never exclude by something an
attacker controls — excluding a username or a filename exempts anyone who can set
that value.

If a rule needs the same exclusion in every environment, the rule's logic is
wrong. Fix the logic.

## Who decides

| Change | Who |
|--------|-----|
| New `draft` or `experimental` rule | Author, one reviewer |
| Promotion to `stable` | Author, one reviewer, evidence from the soak |
| Tuning an existing rule | Author, one reviewer, plus what it makes invisible |
| Deprecation | Author, one reviewer, plus what replaces it |
| Schema, rubric, or environment change | Two reviewers (`CODEOWNERS`) |
