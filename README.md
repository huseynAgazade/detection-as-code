<div align="center">

# Detection as Code

**Detection engineering with the discipline of software engineering:
every rule is reviewed, validated, scored, and built from a single source of truth.**

[![Detection CI](https://github.com/your-org/detection-as-code/actions/workflows/detection-ci.yml/badge.svg)](https://github.com/your-org/detection-as-code/actions/workflows/detection-ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

</div>

---

## The problem this solves

Most SOCs write detections in the SIEM's own console. It works, right up until it
does not: there is no history of who changed a threshold or why, no review before
a rule reaches production, no way to run the same logic on a second platform, and
no answer to "what are we blind to?" that does not involve a spreadsheet someone
last updated in March.

This repository treats detections the way a functioning engineering team treats
code. A rule is a reviewed file. It is validated automatically, assessed for
quality before merge, rendered per environment by a build stage, and traceable
from the alert an analyst receives back to the commit that created it.

## How it works

```
      detections/*.yaml                       environments/<env>/
   one portable rule per file            variables + tuning per environment
              │                                        │
              └───────────────┬────────────────────────┘
                              ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  1  VALIDATE     schema · conventions · consistency          │  offline
   │                  quality gates · sensitive-value scan        │  no API key
   ├──────────────────────────────────────────────────────────────┤
   │  2  AI REVIEW    six weighted dimensions → quality score     │  gated at 70
   │                  posted to the pull request, gates the merge │  /100
   ├──────────────────────────────────────────────────────────────┤
   │  3  BUILD        render per environment → dist/ + manifest   │  deployable
   └──────────────────────────────────────────────────────────────┘
                              ▼
              dist/<env>/<platform>/<RULE-ID>.yaml
```

A rule is written once, in a platform-neutral file with the environment-specific
parts left as placeholders. The build stage resolves those placeholders against
an environment and emits something a deployment job can hand to a platform API.
The same rule can therefore run in a lab with loose thresholds and in production
with tuned ones, without two copies of it existing anywhere.

## Repository layout

```
detections/            The catalogue. One rule per file, organised by category.
  identity/            ID-*     directory services, VPN, SSO
  endpoint/            EDR-*    process, file, and registry activity
  network/             NET-*    traffic, DNS, firewall
  os/                  OS-*     operating-system telemetry
  cloud/               CLD-*    control-plane and identity events
  web/                 WEB-*    WAF, proxy, application logs
  operational/         OPS-*    detection health and telemetry coverage

environments/          What differs between deployments.
  _base/               Defaults every environment inherits
  lab/                 Loose thresholds, all platforms, for development
  production/          Tuned thresholds and reviewed exclusions

schemas/               The contract a rule file must satisfy
templates/             Starting point for a new rule
pipelines/             The pipeline: validate, review, build, tools
docs/                  Guides, and the generated coverage report
tests/                 Pipeline test suite
```

## Quick start

```bash
git clone https://github.com/your-org/detection-as-code.git
cd detection-as-code
make install

make validate         # stage 1 - structure, quality gates, sensitive values
make build            # stage 3 - render dist/ for every environment
make test             # the pipeline's own test suite
```

Everything above runs offline. Stage 2 needs an API key:

```bash
export ANTHROPIC_API_KEY=...
make review           # score the rules changed against main
```

To start a new detection:

```bash
make new CATEGORY=identity/active_directory SUBJECT=AD NAME="Kerberos Pre-Authentication Disabled"
```

The scaffolder allocates the next free rule ID for that category, fills in the
dates, and writes a file that already passes structure validation — so the work
starts at the query rather than at the boilerplate.

---

## Stage 1 — Validation

Deterministic, offline, and free. It runs on every commit and answers one
question: *is this a well-formed detection that will not break something?*

Three layers, most fatal first:

| Layer | What it checks |
|-------|----------------|
| **Structure** | JSON Schema conformance; rule ID uniqueness and prefix-to-directory convention; filenames matching rule names; declared platforms matching implemented query blocks; ATT&CK names matching ATT&CK IDs; lifecycle coherence; every `{{ placeholder }}` resolving against the base variables |
| **Quality gates** | Unbounded searches (`index=*`, `union *`); expensive constructs (`join`, `transaction`, `append`); missing alert throttling; throttle and risk fields the query never emits; a `stable` rule with no documented false positives, triage steps, or references; descriptions that only restate the title |
| **Sensitive values** | Credentials, tokens, private keys, routable public IP addresses, corporate email addresses, internal hostnames, and links to internal systems — anywhere in the catalogue |

The third layer exists because tuning is how environments leak. An exclusion
added at 2am names a real server; a reference links an internal ticket. Once the
repository is shared, that is permanent. So the scan fails the build, and the
exception path is a reviewed entry in
[`pipelines/validate/allowlist.txt`](pipelines/validate/allowlist.txt) — the point
being that someone approved it in a diff.

Findings are emitted as GitHub annotations, so they appear on the pull request
diff rather than only in a job log.

```
$ make validate
Detection catalogue: 7 rule(s) under detections/
  -> structure    (schema, conventions, internal consistency)
  -> quality      (query scope, alert hygiene, analyst context)
  -> sensitive    (credentials, public addresses, internal references)

0 error(s), 0 warning(s)

Validation passed.
```

## Stage 2 — AI quality review

Validation proves a rule is *well-formed*. It cannot tell you whether the rule is
any *good* — whether the query detects what the description claims, whether it
will bury the SOC on a Tuesday, whether an analyst receiving the alert can do
anything with it. Those are judgement calls, and this stage makes them, scores
them, and gates the merge on the result.

Each rule is scored 0–100 on six weighted dimensions:

| Dimension | Weight | The question it answers |
|-----------|-------:|-------------------------|
| Detection logic | 25% | Does the query actually detect the behaviour the description claims? |
| False-positive resilience | 22% | On a normal week of real traffic, is the alert volume workable? |
| Triage readiness | 18% | Can an analyst who has never seen this alert act on it? |
| Metadata and ATT&CK accuracy | 15% | Do the mapping, severity, and confidence honestly describe the logic? |
| Performance and cost | 12% | Will it run at this cadence on production volumes? |
| Evasion resistance | 8% | How much effort does staying under it actually take? |

The weights encode a position: a rule that does not detect what it claims is
worthless, so logic carries the most weight — but false-positive resilience and
triage readiness together outweigh it, because a correct rule nobody can work is
a rule that gets muted.

**The overall score is computed in Python from the per-dimension scores, not
asked of the model.** Arithmetic is not a judgement call, and a self-reported
total cannot be audited against the dimensions that supposedly produced it.

| Score | Verdict | What happens |
|-------|---------|--------------|
| 85–100 | `PASS` | Meets the bar |
| 70–84 | `REVIEW` | Merges, but a human is asked to look |
| below 70 | `BLOCK` | Pipeline fails |
| any blocking issue | `BLOCK` | Regardless of score |

The rubric, its calibration anchors, and the thresholds live in
[`pipelines/review/rubric.py`](pipelines/review/rubric.py) — one reviewed file, so
a score in an old report can still be interpreted against the rubric that
produced it. The full report is posted as a pull request comment.

Three deliberate behaviours:

- **Only changed rules are reviewed.** The stage costs money per rule; a pull
  request pays for what it touched.
- **A refusal or an API error never reports as a pass.** An unreviewed rule is
  reported as unreviewed, because a review that fails open is worse than no
  review at all.
- **Missing credentials skip the stage rather than failing it**, so a fork or an
  offline contributor is not blocked by a secret they cannot have. Branch
  protection is what makes the review mandatory where it matters.

## Stage 3 — Build

Renders each rule against each environment and writes deployable output:

```
dist/production/splunk/ID-AD-001.yaml
dist/production/sentinel/ID-AD-001.yaml
dist/production/manifest.json
```

Jinja runs with `StrictUndefined`, so a typo in a variable name fails the build
instead of quietly rendering `index= ` into a query that then matches everything
or nothing.

The manifest records what an environment is supposed to be running — rule IDs,
versions, and the reason anything in the catalogue was left out. A deployment job
compares it against what the platform actually has, which is how a rule that was
disabled six months ago and never removed gets noticed.

```
$ make build
lab              9 rule/platform artefact(s), 0 skipped  [elastic, splunk]
production       9 rule/platform artefact(s), 1 skipped  [sentinel, splunk]
                 - WEB-WAF-001: Soak window ends 2026-09-02; promote after review of lab findings.
```

`dist/` is generated and git-ignored. Committing it would create a second source
of truth, and the second one always wins arguments it should lose.

---

## Anatomy of a detection

```yaml
metadata:
  id: "ID-AD-001"                       # stable forever; never reused
  name: "Kerberoasting via RC4 Service Ticket Request"
  description: >-                       # this becomes the alert body
    A single account requested Kerberos service tickets for an unusual number
    of distinct service principal names within one hour, with RC4-HMAC
    encryption selected...
  status: "stable"                      # draft → experimental → stable
  severity: "high"                      # impact if it is a true positive
  confidence: "medium"                  # likelihood that a hit is one

  mitre:
    - tactic: "Credential Access"
      tactic_id: "TA0006"
      technique: "Steal or Forge Kerberos Tickets: Kerberoasting"
      technique_id: "T1558.003"

  data_sources: ["Windows Security Event Log"]
  platforms: [splunk, sentinel]

  risk:                                 # platform-neutral alert framing
    objects:
      - { field: "account", type: "user", score: 70 }
    message: "Account $account$ requested RC4 tickets for $distinct_spns$ SPNs from $src$."

  false_positives: ["Vulnerability scanners enumerate SPNs by design..."]
  triage: ["Confirm whether the requesting account is a human user or a service identity..."]
  references: ["https://attack.mitre.org/techniques/T1558/003/"]

detection:
  splunk:
    schedule: { cron: "{{ schedule.standard }}", earliest: "-70m", latest: "-10m" }
    query: |
      index={{ index.windows }} EventCode=4769 Ticket_Encryption_Type="0x17"
          {{ exclusions.splunk.kerberoasting_known_enumerators | default("") }}
      | stats dc(spn) AS distinct_spns BY _time, account, src
      | where distinct_spns >= {{ thresholds.kerberoast_distinct_spns }}
    throttle: { fields: ["account"], period: "12h" }
```

Two conventions carry most of the weight.

**Severity and confidence are separate.** Severity is the impact of a true
positive; confidence is how likely a hit is to be one. `high` severity with
`medium` confidence is a valid and common combination, and it tells triage to
corroborate before escalating — information that a single "severity" field
cannot carry.

**`false_positives` and `triage` are required for a `stable` rule**, enforced by
the quality gates. Missing analyst context is not a documentation nit. It is paid
for on every single alert, by whoever is on shift.

## Environments and tuning

A detection never contains anything environment-specific. Index names, table
names, thresholds, and schedules are placeholders resolved at build time:

```yaml
# environments/production/variables.yaml
index:
  windows: "wineventlog"
thresholds:
  kerberoast_distinct_spns: 8       # lab uses 3
rules:
  WEB-WAF-001:
    enabled: false
    reason: "Soak window ends 2026-09-02; promote after review of lab findings."
```

Tuning that is true for one environment only goes in that environment's
`exclusions.yaml`, referenced by name from the rule:

```yaml
exclusions:
  splunk:
    # Authenticated vulnerability scanners enumerate SPNs as part of their AD
    # assessment. Scoped to the scanner hosts rather than to the account, so a
    # stolen scanner credential used from anywhere else still alerts.
    kerberoasting_known_enumerators: |-
      NOT Client_Address IN ("192.0.2.24", "192.0.2.25")
```

Every exclusion is a deliberate blind spot, so every exclusion carries a comment
saying what it hides and why. Referencing an undefined name renders nothing
rather than failing, as long as the call site chains `| default("")` — so an
environment only defines the tuning it actually needs.

## Detection lifecycle

```
draft ──────────► experimental ──────────► stable ──────────► deprecated
  │                    │                      │
  not deployed         deployed, on a         production;
  anywhere             soak window with       reviewed on change
                       an owner and a
                       deadline
```

A rule enters production as `experimental` with a soak window. When the window
closes it is promoted, extended with a reason, or retired — and the weekly
[catalogue health](.github/workflows/catalogue-health.yml) job fails until
someone decides:

```
$ python -m pipelines.tools.soak_report
1 rule(s) in a soak window:

  WEB-WAF-001  4d left    started 2026-08-12 (17/21 days, owner: huseyn.aghazada)
```

The same job validates in strict mode, where warnings are errors, and fails if
the coverage report has drifted from the rules it describes.

## Coverage

[`docs/coverage.md`](docs/coverage.md) is generated from the catalogue by
`make coverage`: ATT&CK tactic coverage, platform coverage, lifecycle status, and
the log sources every rule depends on. Because it is generated, it cannot drift
into being a document about what the coverage used to be.

---

## Documentation

| Guide | What it covers |
|-------|----------------|
| [Writing detections](docs/writing-detections.md) | Field-by-field authoring guide and the conventions behind it |
| [The pipeline](docs/pipeline.md) | What each stage does, how to run it locally, branch protection |
| [AI review](docs/ai-review.md) | The rubric, calibration, cost, and what the score does and does not mean |
| [Lifecycle](docs/lifecycle.md) | Promotion, tuning, deprecation, and who decides |
| [Coverage](docs/coverage.md) | Generated ATT&CK and platform coverage |
| [Contributing](CONTRIBUTING.md) | How to propose a change and what review will ask for |

## Design decisions

**Why is the ATT&CK tactic table checked in rather than fetched?**
CI must give the same answer offline as online. A mapping that silently changes
meaning between two runs is worse than one that is a release behind. The table
lives in [`pipelines/lib/mitre.py`](pipelines/lib/mitre.py) with an alias
mechanism, so a rename in ATT&CK warns rather than breaking the pipeline on the
day it lands.

**Why not let the AI stage do the structural checks too?**
Anything that can be stated as a rule should be stated as a rule: it runs for
free, on every commit, with the same answer every time. The model's attention is
spent on the parts that genuinely need judgement, and its findings are not
diluted by things a regular expression could have caught.

**Why is the build output not committed?**
It is derived from `detections/` and `environments/`. Committing it creates a
second source of truth, and in every argument between the two, the wrong one
wins.

**Why does an unreviewed rule fail rather than pass?**
Because the alternative is a review stage that fails open — green when the API is
down, green when a rule trips a safety classifier, green when the credentials
expired. A gate that cannot fail is not a gate.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). In short: `make check` before you open a
pull request, document the false positives, and say what you tested the rule on.
"It parses" is not testing.

## License

[MIT](LICENSE).
