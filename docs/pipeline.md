# The pipeline

Three stages. Each answers a different question, and each is runnable locally
with the same arguments CI uses — if `make check` passes on your machine, the
offline jobs pass in CI.

| Stage | Question | Cost | Needs credentials |
|-------|----------|------|-------------------|
| Validate | Is this a well-formed detection? | Free | No |
| Review | Is this a good detection? | Per rule reviewed | Yes |
| Build | Does it still resolve for every environment? | Free | No |

## Stage 1 — Validate

```bash
python -m pipelines.validate                    # everything, warnings are advisory
python -m pipelines.validate --strict            # warnings become errors
python -m pipelines.validate --skip sensitive    # narrow a debugging run
```

### Structure

Schema conformance against `schemas/detection.schema.json`, then the conventions
that keep the catalogue navigable once it holds several hundred rules:

- Rule IDs are unique, and the prefix matches the directory
  (`identity/` → `ID-*`), so an ID alone tells you where the rule lives.
- Detections live in a category directory, never loose in `detections/`.
- Filenames match rule names, so a rename shows up in the diff.
- `metadata.platforms` and the `detection:` blocks describe the same set. A
  platform declared but not implemented builds nothing; a block that is not
  declared never gets built. Both look like coverage that does not exist.
- ATT&CK names match their IDs, and no pair is mapped twice.
- `status: experimental` has a soak start and an owner.
- Risk objects and `$placeholders$` name fields the query actually emits.
- Every `{{ jinja }}` placeholder resolves against `environments/_base`, so a
  typo fails here with the rule's name rather than later with a stack trace.

### Quality gates

Deterministic checks that sit between the schema and the model — objectively true
or false, and cheap:

| Check | Level | Why |
|-------|-------|-----|
| `index=*`, `sourcetype=*`, `union *` | error | An unbounded scheduled search is the first thing disabled when the platform is under load |
| `join`, `transaction`, `append*` | warning | Subquery- and memory-bounded; they truncate silently rather than failing |
| No throttle | warning | One noisy source becomes one alert per scheduled run |
| Throttle or risk field the query never emits | warning | De-duplication and the alert body both break quietly |
| `stable` without `false_positives` / `triage` / `references` / `risk` | error | Missing analyst context is paid for on every alert |
| Description restating the title | error | The description is the alert body |
| `modified` before `created` | error | Usually a copy-paste from another rule |

### Sensitive values

Scans the whole catalogue for credentials, tokens, private keys, routable public
IP addresses, corporate email addresses, internal hostnames, and links to
internal systems. Documentation ranges (RFC 5737) and reserved example domains
(RFC 2606) are always accepted — they exist so examples do not need real values.

Exceptions go in `pipelines/validate/allowlist.txt`, which is a reviewed file:
the point is not that exceptions are impossible, but that each one appears in a
diff with a name against it.

## Stage 2 — Review

See [ai-review.md](ai-review.md) for the rubric and what the score means.

```bash
python -m pipelines.review --changed-from origin/main   # what a pull request runs
python -m pipelines.review --rule ID-AD-001             # one rule
python -m pipelines.review --all --no-gate              # score the catalogue, report only
```

## Stage 3 — Build

```bash
python -m pipelines.build --output dist/
python -m pipelines.build --environment production
```

For each environment, for each rule that is buildable there, for each platform
enabled in both: resolve the placeholders and write
`dist/<env>/<platform>/<RULE-ID>.yaml`.

A rule is skipped, with the reason recorded in the manifest, when:

- its status is `draft` or `deprecated`;
- the environment sets `rules.<id>.enabled: false`;
- none of the rule's platforms is enabled in that environment.

Jinja runs with `StrictUndefined`. An undefined variable is a build failure, not
an empty string — the difference between a loud failure and a query that quietly
matches everything.

### The manifest

`dist/<env>/manifest.json` records the rule IDs, versions, statuses, and
platforms that environment should be running, plus everything that was skipped
and why. A deployment job diffs it against what the platform actually has, which
is how a rule that was disabled six months ago and never removed gets noticed.

## Running it in GitHub Actions

[`.github/workflows/detection-ci.yml`](../.github/workflows/detection-ci.yml)
runs validate → (review, build). Review runs only on pull requests, only for
changed rules, and posts its report as a comment.

### Required secrets and variables

| Name | Type | Purpose |
|------|------|---------|
| `ANTHROPIC_API_KEY` | secret | Stage 2. Without it the stage skips rather than failing |
| `DETECTION_REVIEW_MODEL` | variable | Optional. Overrides the review model |

### Branch protection

The review stage skips without credentials so that forks are not blocked by a
secret they cannot have. That is only safe if the branch itself is protected.
On `main`, require:

- `Validate structure`
- `Build environment packages`
- `AI quality review`
- At least one human approval, with `CODEOWNERS` review for `schemas/`,
  `pipelines/review/`, and `environments/`

### Weekly health check

[`catalogue-health.yml`](../.github/workflows/catalogue-health.yml) runs every
Monday and fails if:

- strict validation finds anything — warnings accumulate into a backlog rather
  than disappearing;
- `docs/coverage.md` has drifted from the catalogue;
- a soak window has closed without a promotion decision.

## Extending the pipeline

**A new platform.** Add it to the schema's `platforms` enum with its own block
definition, to `SUPPORTED_PLATFORMS` in `pipelines/lib/catalog.py`, and to the
`platforms:` map in `environments/_base/variables.yaml`. The build stage needs no
change: it renders whatever blocks a rule declares.

**A new category.** Create the directory and add its ID prefix to
`CATEGORY_PREFIXES` in `pipelines/lib/catalog.py`. Until you do, rules there
validate with a warning rather than failing, so adding a category never breaks
the pipeline before someone updates the map.

**A new deterministic check.** Add it to `pipelines/validate/quality_gates.py`
with a test in `tests/test_quality_gates.py`. Prefer this over asking the model:
it runs for free, on every commit, with the same answer every time.
