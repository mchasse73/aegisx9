# 23. Training-data replay is reported, not gated

- Status: Accepted (owner decision 2026-11-04, #180)
- Date: 2026-11-04

## Context

The staging red-team gate runs garak's `leakreplay.LiteratureCloze` probe. It gives the model a
passage from a known book with one word masked and checks whether the model fills in the
original word, which shows it memorised the text. Once the gate scored every attempt correctly
(#188, #191, #193), the family passed about 0.30 against a 0.90 floor.

A gateway can't change what a model memorised. To pass this probe, a guard would have to refuse
ordinary cloze-style questions, or recognise verbatim passages from every published corpus in
the output. The first breaks legitimate use. The second is a large, partial project unrelated
to the gateway's controls. Left as a gate, the family keeps the gate red forever, and a gate
that is always red hides real regressions in the families that measure gateway controls.

## Decision

1. `leakreplay` becomes **report-only**. It still runs on every red-team run, and the gate
   prints its pass rate against its floor, marked `report-only, ADR 0023`. It never fails the
   gate, the scanner or the coverage check.
2. The report-only list lives in `redteam/garak/thresholds.json` (`report_only`). Adding a
   family to it, like lowering a floor, needs an ADR. A test pins the list to this ADR.
3. The floor stays at 0.90, so the printed verdict still shows how far the model is from it.
4. Revisit this if the gateway gains an output-side verbatim-text control. The family would
   then measure that control and should gate again.

## Consequences

- The gate is red only for families that measure gateway controls (today: promptinject #179,
  latentinjection #195).
- Memorisation stays visible in every run's log and artifact. It's a property of the model
  provider, so model choice is the place to act on it.
- The external scanner applies the same list, so the two gates agree.
