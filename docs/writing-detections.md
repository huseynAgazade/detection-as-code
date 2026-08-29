# Writing detections

A field-by-field guide to `detections/**.yaml`, and the reasoning behind the
conventions. The contract itself is `schemas/detection.schema.json`; this
explains what the fields are *for*.

## Start here

```bash
make new CATEGORY=identity/active_directory SUBJECT=AD NAME="Kerberos Pre-Authentication Disabled"
```

The scaffolder allocates the next free ID for the category, fills in the dates,
and writes a file that already passes structure validation.

## Order of work

Write the description first, then the query, then the analyst context. This is
not stylistic. A description you cannot write in three sentences describes a
behaviour you have not pinned down, and a query for a behaviour you have not
pinned down detects something adjacent to what you wanted.

## `metadata`

### `id`

`<CATEGORY>-<SUBJECT>-<NNN>`, for example `ID-AD-001`. The prefix is determined
by the directory and is enforced by validation, so an ID alone tells you where
the rule lives.

**An ID is permanent.** It appears in alert history, incident records, exception
tickets, and metrics. Never reuse one, never renumber. A retired rule keeps its
ID with `status: deprecated`.

### `name`

Specific, human-readable, and the same as the filename. "Kerberoasting via RC4
Service Ticket Request", not "Kerberos Alert" and not "AD-Detection-7".

### `description`

**This becomes the alert body.** It is read far more often than the query, by
people who did not write it and are looking at it for the first time under time
pressure. Cover:

- what behaviour fired the rule;
- why that behaviour matters — the attacker objective;
- what the results contain, so the reader knows what they are looking at;
- what it is *not*, when there is an obvious adjacent thing it could be confused
  with.

The quality gates reject a description that only restates the name.

### `severity` and `confidence`

Two axes, deliberately separate:

- **`severity`** — the impact if this is a true positive.
- **`confidence`** — how likely a hit is to be one.

`high` severity with `low` confidence is valid and common: something serious *if*
real, but needing corroboration first. Collapsing them into one field loses
exactly the information triage needs. A `critical` / `low` combination is flagged
by the quality gates, because it pages someone for a finding the rule itself does
not trust.

### `mitre`

One entry per tactic/technique pair the rule genuinely covers. Map what the query
matches, not the worst case it could be part of. Stretching a mapping to claim
coverage produces a heat map that says you are covered when you are not, which is
worse than a heat map with a hole in it.

Tactic names must match their IDs; the table is
[`pipelines/lib/mitre.py`](../pipelines/lib/mitre.py).

### `data_sources`

Vendor-neutral names for the logs the rule depends on ("Windows Security Event
Log", "DNS Query Logs"). These drive the coverage report and the onboarding
checklist for a new environment: they are how "we cannot deploy these eleven
rules until DNS logging is on" becomes answerable.

### `platforms`

Must match the `detection:` blocks exactly. Validation enforces both directions,
because a mismatch in either direction looks like coverage that does not exist.

### `risk`

Platform-neutral alert framing, rendered into notable events or incidents at
build time.

```yaml
risk:
  objects:
    - { field: "account", type: "user", score: 70 }
    - { field: "src", type: "system", score: 60 }
  message: "Account $account$ requested RC4 tickets for $distinct_spns$ SPNs from $src$."
```

Every `field` and every `$placeholder$` must be a field the query emits —
validation warns when one is not, because the alert would otherwise render with
an empty value in it.

### `false_positives`

**Required for a `stable` rule.** Document the benign causes you actually
observed while testing, not the ones you imagine. Each entry should be specific
enough that an analyst can confirm or rule it out from the alert.

This is the field a reviewer reads first, because it is the one that proves the
rule met real data.

### `triage`

**Required for a `stable` rule.** Ordered investigation steps: what to check, in
what order, and what would confirm or eliminate the finding. This is the rule's
slice of the runbook, and it lives with the rule so the two cannot drift apart.

### `lifecycle`

For `status: experimental`. `soak_started`, `soak_days`, and an `owner`, so
`pipelines.tools.soak_report` can tell you when a decision is due and who owes
it.

## `detection`

One block per platform. Every block has a `schedule` and a `query`; `throttle` is
optional and almost always wanted.

### Scheduling

Prefer a preset — `{{ schedule.fast }}`, `{{ schedule.standard }}`,
`{{ schedule.slow }}` — so cadence is an environment decision made once rather
than a number copied into every rule.

Leave room for ingestion lag. A rule scheduled at `-20m` to `-5m` covers a
fifteen-minute window that finished five minutes ago; events that arrive late are
still in the index by then. A window ending at `now` silently misses whatever had
not landed yet.

### Query

Three properties matter more than elegance:

**Narrow early.** Filter by index, source type, and event code before anything
expensive. The difference between filtering first and filtering last is the
difference between a rule that runs and a rule that gets disabled.

**Aggregate, do not enumerate.** Alert on a pattern — a count, a distinct count,
a rate — rather than on every matching event. This is what makes the difference
between one alert describing a channel and four hundred alerts describing
individual packets.

**Project explicitly.** End with `table` / `project` / `KEEP`. The analyst should
receive the evidence, not raw events to sift.

Avoid `join`, `transaction`, and `append` where `stats` will do: they are bounded
by subquery and memory limits and truncate silently rather than failing.

### Placeholders

Anything environment-specific is a placeholder:

```yaml
query: |
  index={{ index.windows }} EventCode=4769
      {{ exclusions.splunk.kerberoasting_known_enumerators | default("") }}
  | where distinct_spns >= {{ thresholds.kerberoast_distinct_spns }}
```

Two rules:

1. **Always chain `| default("")` on an exclusion**, so an environment that has
   not defined that name renders nothing instead of failing the build.
2. **Put an exclusion placeholder alone on its line.** Multi-line values are
   re-indented to the placeholder's own column so they stay inside the YAML block
   scalar; a placeholder sharing a line with other query text does not get that
   treatment, and the rendered file will not parse.

### `throttle`

```yaml
throttle:
  fields: ["account"]
  period: "12h"
```

Choose the field that identifies the *thing* the alert is about — the account, the
host, the channel. Without throttling, a single noisy source produces one alert
per scheduled run, which is how a correct rule becomes an ignored one.

## Testing before you commit

1. Run the query over a representative period — a week, not an hour.
2. Count the hits, and work a sample of them as if you were on shift.
3. Write down what came back benign. That is your `false_positives` list.
4. Estimate daily volume. If the SOC cannot absorb it, tune before merging, not
   after.
5. `make validate`, and `make review` if you have an API key.

Open the rule as `experimental` with a soak window unless it has already run in
production for weeks. `stable` is a claim about evidence.
