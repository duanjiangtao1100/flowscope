# 2026-02-18 LT02 Indentation Engine Parity Project

## Goal

Reach practical LT02 parity with SQLFluff on the production corpus used in parity replay, with reproducible progress metrics and low-regression rollout.

This project is intentionally isolated to indentation behavior so we can iterate fast without cross-rule noise.

## Baseline (captured on 2026-02-18)

- Corpus: 85 PostgreSQL `.sql` files
- FlowScope LT02: `386 -> 388` (delta `+2`, regression)
- SQLFluff LT02: `1059 -> 0` (delta `-1059`)
- LT02 parity gap after fix: `388`
- LT01 is now at parity in the same run (`9 -> 0` for FlowScope, `0 -> 0` for SQLFluff), so LT02 is the only remaining gap in this corpus replay.

## Pass 1 Results (2026-02-18)

First dedicated engine pass implemented for high-impact patterns:

- Inline keyword breaks with continuation indentation:
  - `WHERE <expr>` + following `AND/OR` lines
  - `ON <expr>` + following `AND/OR` lines
  - `SET <assignment>` + following assignment continuation lines
- Postgres issue emission now carries autofix patches for these LT02 locations instead of report-only spans.

Measured with LT02-only workbench on the same corpus:

- FlowScope LT02: `842 -> 50` (reduced `792`)
- SQLFluff LT02: `1112 -> 0` (reduced `1112`)
- LT02 parity gap after fix: `320` (down from `1112`)

Residual buckets after pass 1:

- `general-structural`: 29
- `case-block`: 13
- `closing-bracket-alignment`: 6
- `join-on-block`: 2

Note on all-rules runs: LT02-only parity improves much faster than full all-rules fix runs because global regression guards can skip valid LT02 edits when unrelated rule totals increase in the same file.

## Pass 2-11 Results (2026-02-18)

Additional LT02 engine passes landed:

- Nested subquery continuation indentation inside `WHERE/ON` blocks now tracks parenthesis depth through clause keywords.
- Inline `JOIN ... ON ...` handling was narrowed to SQLFluff-like split patterns (especially `INNER`/`JOIN` split forms) to avoid broad over-reporting.
- Postgres LT02 issue emission was tuned to avoid duplicate `SET` report spans that over-counted against SQLFluff.
- Added focused regression tests for:
  - nested subquery indentation under `WHERE`
  - inline `JOIN ... ON ...` with operator continuation

Additional LT02 engine and emission updates:

- Removed LT02 multiline bracket-spacing side effects that were creating LT01 regressions.
- Switched Postgres LT02 issue emission to one issue per autofix edit (no same-line collapsing), which recovered a large undercount vs SQLFluff.
- Added targeted continuation handling for:
  - `WHEN` condition chains (`AND/OR`)
  - `THEN` indentation expectations
  - `MAKE_INTERVAL(days => ...)` multiline argument/close-paren structures

Measured with LT02-only workbench on the same corpus:

- FlowScope LT02: `1106 -> 0` (reduced `1106`)
- SQLFluff LT02: `1112 -> 0` (reduced `1112`)
- LT02 parity gap after fix: `6`

Measured in full all-rules replay:

- FlowScope: `1408 -> 293`
- SQLFluff: `1414 -> 293`
- Remaining parity gap is LT02-only (`6`).

## Pass 12 Results (2026-02-18)

Final LT02 parity closures landed:

- `WHERE` inline conditions now break/indent when the continuation line starts with an operator (`=`, etc.), not only `AND/OR`.
- Targeted trailing `AS` alias-break autofix for split select aliases (`expr AS` + alias on next line).

Measured with LT02-only workbench on the same corpus:

- FlowScope LT02: `1112 -> 0` (reduced `1112`)
- SQLFluff LT02: `1112 -> 0` (reduced `1112`)
- LT02 parity gap after fix: `0`

Measured in full all-rules replay:

- FlowScope: `1414 -> 293`
- SQLFluff: `1414 -> 293`
- Full parity gap: `0`

## Dedicated Workbench

Use LT02-only tooling to avoid unrelated rule interactions:

```bash
just lt02-corpus-parity /path/to/sql-corpus /path/to/sqlfluff
```

or directly:

```bash
python3 scripts/lt02-indent-parity-workbench.py \
  --sql-dir /path/to/sql-corpus \
  --sqlfluff-bin /path/to/sqlfluff \
  --dialect postgres \
  --json-output /tmp/lt02-report.json
```

The workbench reports:

- LT02 before/after totals for both tools
- FlowScope fix telemetry (applied/skipped/blocked)
- grouped FlowScope LT02 residuals after fix
- after-fix divergence sets (FlowScope-only vs SQLFluff-only locations)

## Architecture Direction

Current LT02 behavior is largely heuristic and line-local. SQLFluff parity on complex indentation requires a dedicated indentation engine with a structural context stack and deterministic reindent planning.

Proposed engine shape:

1. Parse-to-layout IR
2. Build indentation context stack (clause blocks, bracket scopes, CASE, JOIN/ON, set ops, CTEs)
3. Compute expected indent per line from context transitions
4. Emit stable leading-whitespace patches from expected-vs-actual diff
5. Validate no parse-error increase and no cross-line patch conflicts

## Milestones

### M0: Instrumentation Complete

- [x] LT02-only parity workbench script in-repo
- [x] Reproducible command in `justfile`
- Exit criterion: every run emits same baseline metrics and grouped residuals

### M1: Stop LT02 Regressions

- [x] Ensure FlowScope LT02 never increases after fix (`after <= before`) on corpus replay
- [ ] Add regression tests for currently observed increase patterns
- Exit criterion: no `LT02 +delta` on corpus replay

### M2: High-Impact Gap Reduction

- [ ] Implement structural-indent engine pass for the top residual groups from workbench output
- [ ] Land targeted fixtures per residual group
- Exit criterion: LT02 parity gap reduced by at least 50%

### M3: Near-Full Parity

- [ ] Cover remaining groups (hanger/continuation, CASE/JOIN, bracket close alignment, templated-safe paths)
- [ ] Harden patch planner conflict handling
- Exit criterion: LT02 parity gap <= 25 with no new regressions in other layout rules

### M4: Full Corpus Parity

- [x] Close final LT02 divergences in LT02-only corpus replay (gap: `0`)
- [x] Keep SQLFluff fixture parity for LT02 green
- Exit criterion: LT02 parity gap `0` on target corpus and no fixture regressions

## Immediate Next Tasks

1. Freeze this corpus as a regression gate in CI (`just lt02-corpus-parity` + full `just sql-corpus-parity`).
2. Expand fixture coverage for LT02 split-token continuation patterns (`WHERE` operator lines, trailing `AS` alias breaks).
3. Start the dedicated next-phase indentation engine project on structural context stack replacement of heuristic passes.
