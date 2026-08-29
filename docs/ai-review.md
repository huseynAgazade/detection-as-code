# AI quality review

Stage 1 proves a rule is well-formed. It cannot tell you whether the rule is any
good — whether the query detects what the description claims, whether it will
bury the SOC on a Tuesday, whether the analyst who receives the alert can do
anything with it. Those are judgement calls. This stage makes them, scores them,
and gates the merge on the result.

## The rubric

Six dimensions, weighted, defined in
[`pipelines/review/rubric.py`](../pipelines/review/rubric.py):

| Dimension | Weight | What it judges |
|-----------|-------:|----------------|
| `logic_soundness` | 25% | Whether the query, read as written, detects the described behaviour on the named data sources. Field names, filter interaction, aggregation boundaries |
| `false_positive_resilience` | 22% | The shape of benign traffic that would match; whether thresholds are defensible; whether aggregation and throttling collapse a burst into one alert |
| `triage_readiness` | 18% | Whether output fields carry the evidence the triage steps ask for, and whether the description explains rather than restates |
| `metadata_accuracy` | 15% | Whether the ATT&CK mapping, severity, confidence, and data sources honestly describe the logic |
| `performance` | 12% | How early the search narrows; schedule against lookback; cardinality of grouping keys |
| `evasion_resistance` | 8% | Trivial bypasses — exact matches on renameable artefacts, thresholds defeated by pacing |

The weights encode a position. A rule that does not detect what it claims is
worthless, so logic carries the most weight. But false-positive resilience and
triage readiness together outweigh it, because a correct rule the SOC cannot work
is a rule that gets muted — and a muted rule provides exactly as much coverage as
no rule, while looking like coverage on a report.

## Calibration

Scores drift upward without anchors, and a score that only ever lands between 85
and 95 carries no information. The prompt therefore includes explicit bands:

```
90-100  Production-ready. You would merge this as it stands.
75-89   Sound. It works, but there are specific improvements to ask for.
60-74   Workable but flawed. A real weakness that will cost someone time.
40-59   Not ready. Misses a substantial part of what it claims, or is unworkably noisy.
0-39    Broken. Cannot fire, fires on the wrong thing, or would degrade the SOC.
```

Most competent, unremarkable rules should land in the 70s and 80s. A catalogue
where everything scores above 90 is a miscalibrated rubric, not an excellent
catalogue.

## How the score is produced

1. The rule is serialised and sent with the rubric as the system prompt. The
   system prompt is identical for every rule in a run and marked for caching, so
   reviewing forty rules pays for the rubric once.
2. The response is constrained by a JSON schema that requires all six dimensions,
   so parsing cannot fail on prose and a review cannot silently skip the
   dimension it found hardest.
3. **Python computes the weighted total.** Arithmetic is not a judgement call,
   and a self-reported score cannot be audited against the dimensions that
   supposedly produced it.
4. The verdict follows from the score and from whether any blocking issue was
   raised.

| Score | Verdict | Effect |
|-------|---------|--------|
| 85–100 | `PASS` | Meets the bar |
| 70–84 | `REVIEW` | Merges, but a human is asked to look |
| below 70 | `BLOCK` | Pipeline fails |
| any blocking issue, or `detects_what_it_claims: false` | `BLOCK` | Regardless of score |

## Failure behaviour

**An unreviewed rule is never a passing rule.** If the API errors, or the model
declines the request, the result is `ERROR` with a score of zero and the pipeline
fails. A review stage that fails open is green when the API is down, green when
the credentials expired, and green when a rule tripped a safety classifier — a
gate that cannot fail is not a gate.

**Missing credentials skip the stage rather than failing it.** A fork or an
offline contributor should not be blocked by a secret they cannot have. Branch
protection is what makes the review mandatory where it matters; `--require-credentials`
forces a hard failure where that is preferred.

## Cost

Only changed rules are reviewed, so a pull request pays for what it touched. The
run prints an estimate:

```
  mean quality score: 84.2/100 over 3 rule(s)
  estimated cost:     $0.1140 (claude-opus-5)
```

A typical rule is a few thousand input tokens and under a thousand output tokens.
Prompt caching means the rubric — the largest stable part of the request — is
charged once per run rather than once per rule. Set `DETECTION_REVIEW_MODEL` to
review with a cheaper model where the volume justifies it.

## What the score is not

It is not a substitute for testing the rule against real data, and it is not a
substitute for human review. The model reads the rule; it has never seen your
logs, does not know your environment's baseline, and cannot tell you that the
field you referenced was renamed during last quarter's upgrade. A rule that
scores 95 and has never fired on real data is still an unproven rule.

Use the score as a floor and a prompt for discussion — the reasoning in the
report is worth more than the number attached to it.

## Configuration

| Setting | Where | Default |
|---------|-------|---------|
| Model | `DETECTION_REVIEW_MODEL` env var, or `--model` | `claude-opus-5` |
| Block threshold | `rubric.BLOCK_BELOW`, or `--min-score` | 70 |
| Warn threshold | `rubric.WARN_BELOW` | 85 |
| Parallelism | `--concurrency` | 4 |
| Report only | `--no-gate` | off |

Changing a weight or a threshold changes what every past score meant, so both
live in one reviewed file rather than in a prompt string or a workflow input.
