# Contributing

Detections are production code. A rule that is wrong is worse than no rule: it
consumes analyst time, and it creates the belief that something is covered when
it is not. This document is what review will ask you for.

## Before you open a pull request

```bash
make check      # lint, tests, and stage 1 validation - all offline
```

If you have an API key, run the review stage on your own work first. It is
cheaper to read its findings than to have a reviewer read them for you:

```bash
export ANTHROPIC_API_KEY=...
make review
```

## Adding a detection

```bash
make new CATEGORY=identity/active_directory SUBJECT=AD NAME="Kerberos Pre-Authentication Disabled"
```

Then, in roughly this order:

1. **Write the description before the query.** If you cannot describe the
   behaviour in three sentences, the query will not detect it either. The
   description becomes the alert body, so write it for the person reading the
   alert at 3am, not for the person who already knows what you meant.

2. **Write the query, and test it on real data.** Run it over a period long
   enough to be representative — a week, not an hour — and look at what comes
   back. Count the hits. Work a sample of them as if you were on shift.

3. **Document the false positives you found.** Not the ones you imagine: the
   ones that actually came back. This is the field reviewers look at first,
   because it is the one that proves the rule met real data.

4. **Write the triage steps.** What should the analyst check, in what order, and
   what would confirm or rule out the finding.

5. **Map to ATT&CK honestly.** Map what the query matches, not the worst case it
   might be part of. A rule that catches one step of a technique maps to that
   step.

6. **Set severity and confidence separately.** Severity is the impact if it is a
   true positive. Confidence is how likely a hit is to be one. They are not the
   same axis, and collapsing them loses the information triage needs most.

7. **Open it as `experimental` with a soak window**, unless you have already run
   it in production for weeks. `stable` is a claim about evidence.

## Tuning an existing detection

Tuning goes in the environment, not in the rule:

```yaml
# environments/production/exclusions.yaml
exclusions:
  splunk:
    # What this suppresses, and why. Required.
    rule_specific_name: |-
      NOT Client_Address IN ("192.0.2.24")
```

Three rules of thumb:

- **Scope as narrowly as the false positive allows.** A specific parent process
  beats a host, which beats a subnet, which beats a whole account type. Each step
  outward is a larger blind spot.
- **Never exclude by the thing an attacker controls.** Excluding a username or a
  filename means an attacker who can set that value is exempt from the rule.
- **Say what it makes invisible.** Every exclusion is a deliberate blind spot.
  The comment is how the next person knows its shape.

If a rule needs the same exclusion in every environment, the rule's logic is
wrong. Fix the logic.

## What never goes in this repository

The sensitive-value scan enforces this, and it fails the build rather than
warning:

- Real hostnames, internal domains, routable public IP addresses
- Corporate email addresses, usernames, employee names
- Credentials, tokens, API keys, private keys
- Links to internal wikis, tickets, or dashboards
- Anything else that identifies a specific organisation's environment

Use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
`example.com`, or a variable. If a value genuinely has to be real for a rule to
work, it belongs in an environment's `exclusions.yaml` in a repository that is
not shared.

## Changing the pipeline

- Add a test. `tests/` covers the validators, the renderer, and the scoring, and
  a check with no test is a check that will be quietly broken later.
- Deterministic checks go in `pipelines/validate/`. If it can be stated as a
  rule, it should be, so it runs for free on every commit.
- Changes to `schemas/`, `pipelines/review/rubric.py`, or `environments/` affect
  every rule in the repository and need a second reviewer.

## Review

A reviewer will ask:

- Does the query detect what the description says it detects?
- What did you test it on, and what came back?
- What is the alert volume, and can the SOC absorb it?
- What does the analyst do when it fires?
- What does any new exclusion make invisible?

The AI review stage asks the same questions and posts its answers on the pull
request. It is an input to review, not a replacement for it: a high score on a
rule nobody has run against real data still means nothing.
