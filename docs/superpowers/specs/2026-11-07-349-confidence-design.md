# #349: confidence counts GAP probes; separate coverage figure

## Problem

`inBase` excluded every `GAP-*` claim, so closing a bypass probed by a GAP
claim (for example #324, GAP-A10) never moved the headline confidence.

## Decision

- `inBase` = `testable: periodic`. GAP probes that are periodic count like any
  other claim; `manual` and `never` claims stay out.
- Every GAP scenario in `rig/scenarios/gaps.yaml` and `lifecycle.yaml`
  expects the safe behaviour (deny, 401, 400 or 201 for a valid mint), so
  PASS means the bypass is closed. No probe is inverted. A FAIL lowers
  confidence and a PASS raises it.
- New figure: coverage = base claims with at least one runnable (non-GAP)
  scenario result / base. `Summary.Covered`, `Summary.Coverage`,
  `Summary.CoverageText()`; JSON `summary.covered` and `summary.coverage`;
  a `coverage:` line in the text report. The coverage-gap list (base claims
  with no scenario at all) is kept.
- GAP-A4 and GAP-A9 have no scenario yet, so they now appear as GAP in base
  and in the coverage-gap list. That is the honest result.
