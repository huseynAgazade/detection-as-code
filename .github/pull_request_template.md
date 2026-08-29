## What this changes

<!-- One or two sentences. If this adds a detection, say what behaviour it detects. -->

## Type of change

- [ ] New detection
- [ ] Tuning of an existing detection (threshold, exclusion, schedule)
- [ ] Lifecycle change (promotion, deprecation, soak extension)
- [ ] Environment configuration
- [ ] Pipeline or tooling

## For a new or modified detection

- [ ] Tested against real data, and I have said below what I tested it on
- [ ] Known false positives are documented in `metadata.false_positives`
- [ ] `metadata.triage` says what the analyst should do
- [ ] The ATT&CK mapping reflects what the query matches, not what it is near
- [ ] Any tuning that is specific to one environment lives in that
      environment's `exclusions.yaml`, not in the rule
- [ ] `make validate` passes locally

### What I tested it on

<!--
Which environment, what date range, how many hits, and how many of those were
true positives. "It parses" is not testing. If the rule has never fired on real
data, say so and open it as status: draft or experimental.
-->

## Tuning changes only

<!-- What was suppressed, why, and what is now invisible as a result. Every
exclusion is a deliberate blind spot; the next person needs to know its shape. -->

## Reviewer notes

<!-- Anything you are unsure about, or specifically want a second opinion on. -->
