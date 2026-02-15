# Plan: Dialect-Agnostic Lint/Fix Redesign (Patch-Based, Ruff-Style)

## Goal

Replace AST round-trip auto-fix as the default with a patch-based fix engine that:

- works across all supported dialects,
- preserves comments and templated regions,
- classifies fix safety (`safe` vs `unsafe`),
- provides deterministic, conflict-free edit application,
- keeps CLI and editor behavior consistent.

Status (2026-02-14): implemented in `flowscope-cli` with safe/unsafe applicability, deterministic patch planning, protected ranges, CLI flags (`--unsafe-fixes`, `--show-fixes`), and a serve-mode `/api/lint-fix` endpoint.

Status update (2026-02-14, later): core lint diagnostics now carry first-class autofix metadata (`Issue.autofix`), CP002/CP003/RF006/CV001/CV002/CV003/CV004/CV005/CV006/CV007/ST012/TQ003/LT001/LT002/LT003/LT004/LT006/LT007/LT008/LT009/LT010/LT011/LT012/LT013/LT014/LT015/JJ001 emit precise safe patch edits, CLI fix planning consumes core autofix candidates (with core-first conflict priority), and fallback planning applies core-only fixes when mixed rewrite candidates regress.

Status update (2026-02-14, latest): CLI/API default fix path is patch-only; legacy AST rewrite candidates are opt-in via `--legacy-ast-fixes` (CLI) and `legacy_ast_fixes` (`/api/lint-fix`).

## Problem Statement

Legacy behavior (before this redesign) intentionally skipped comment-containing files to avoid losing comments during AST render.

Root causes:

- SQL parser AST render normalizes SQL and drops comment trivia.
- Fix flow currently includes full statement render from AST.
- This blocks auto-fix for many real-world SQL files.

## Non-Goals

- Replacing the parser stack immediately.
- Achieving perfect formatting parity across all dialects in one release.
- Enabling unsafe structural rewrites by default.

## Design Principles

- Preserve original source whenever possible.
- Apply minimal local edits, never full-file rewrite by default.
- Make fix safety explicit and user-controllable.
- Keep behavior deterministic and testable.
- Fail closed: skip uncertain fixes rather than risking corruption.

## Architecture

### 1) Core Data Model

- `Document`: raw SQL text, byte-indexed line table, source metadata.
- `TokenStream`: dialect tokenization with byte spans, including trivia tokens.
- `ParseArtifact`: parsed statements/AST + parser diagnostics.
- `TemplateMap` (optional): mapping between raw and rendered SQL slices.
- `LintDiagnostic`: rule code, message, severity, span, optional fix.

### 2) Rule Interfaces

Rule families:

- `TokenRule`: token-local checks/fixes.
- `AstRule`: semantic checks using parsed structures.
- `LineRule`: line/document style checks.
- `FileRule`: cross-statement or file-global checks.

Each rule emits diagnostics and optional fix candidates.

### 3) Fix Representation

- `Edit`: `{ start_byte, end_byte, replacement }`.
- `Fix`: `{ edits: Vec<Edit>, applicability, isolation_group, rule_code }`.

Applicability levels:

- `Safe`: expected behavior-preserving transform.
- `Unsafe`: may change semantics or has lower confidence.
- `DisplayOnly`: suggested fix shown but never auto-applied.

### 4) Fix Planning and Conflict Resolution

- Collect candidate fixes from all diagnostics.
- Filter by selected safety (`safe` only by default).
- Sort deterministically (`priority`, `start_byte`, `rule_code`).
- Reject overlapping edits unless explicitly mergeable.
- Enforce isolation groups (mutually exclusive transforms).
- Apply edits end-to-start on original source.

### 5) Safety Guards

Protected ranges (default no-edit zones):

- SQL comments,
- string literals,
- templated segments,
- explicitly ignored regions (`noqa` / equivalent when implemented).

Post-apply validation (required for write):

- SQL parses successfully for configured dialect.
- Parse error count does not increase.
- Lint total does not regress (or per-rule objective passes).
- Comment fingerprint unchanged for `Safe` fixes.

### 6) Dialect Layer

Use one shared lint/fix engine with dialect adapters for:

- tokenizer config,
- parser selection,
- quote/comment syntax,
- keyword/feature capability checks.

Rules declare compatibility:

- all dialects,
- explicit dialect allowlist,
- feature-gated dialect behavior.

### 7) Templating Layer

- Render template to analyzable SQL.
- Keep slice mapping raw <-> rendered.
- Map diagnostics/fixes back to raw source spans.
- Reject fixes crossing unmappable or protected template ranges.

### 8) CLI and LSP Contract

CLI:

- `--fix`: apply `Safe` fixes only.
- `--unsafe-fixes`: include `Unsafe` fixes.
- `--legacy-ast-fixes`: opt into legacy AST rewrite candidates.
- `--show-fixes`: show blocked/display-only fix suggestions.

LSP:

- quick-fix and fix-all use same planner and safety semantics.
- consistent diagnostics/fix behavior with CLI.

## Phased Execution Plan

Current completion snapshot:

- Phase 0: complete in CLI (`fix_engine` module, applicability model, deterministic planner, protected ranges).
- Phase 1: actively migrated with core-emitted patch edits for CP002/CP003/RF006/CV001/CV002/CV003/CV004/CV005/CV006/CV007/ST012/TQ003/LT001/LT002/LT003/LT004/LT006/LT007/LT008/LT009/LT010/LT011/LT012/LT013/LT014/LT015/JJ001 and CLI ingestion; CP002/CP003/RF006/CV001/CV002/CV003/CV004/CV005/CV006/CV007/ST012/TQ003/LT001/LT002/LT003/LT004/LT006/LT007/LT008/LT009/LT010/LT011/LT012/LT013/LT014/LT015/JJ001 legacy AST/text rewrite paths removed in favor of core patch metadata.
- Phase 2: complete for applicability plumbing (`Safe`/`Unsafe`/`DisplayOnly`) and CLI reporting of skipped/blocked counts.
- Phase 3: validated on existing multi-dialect core fixture matrix (`cargo test -p flowscope-core`), with migrated rules exercised through parser/token adapters.
- Phase 4: protected template/comment/string ranges enforced in planner; safe mode blocks unstable template edits.
- Phase 5: complete for default execution path (patch-only in CLI/API), with legacy AST rewrites retained as explicit opt-in for non-migrated parity rules.

## Phase 0: Foundations

1. Add fix applicability model (`Safe`, `Unsafe`, `DisplayOnly`).
2. Add normalized `Edit`/`Fix` data structures.
3. Add deterministic patch applier + overlap resolver.
4. Add protected-range utility (comments/literals/template spans).

Deliverable:

- New fix engine crate/module usable from CLI and tests.

## Phase 1: Migrate Existing Deterministic Text Fixes

1. Move current text-safe rules to emit patch edits instead of rewriting full statements.
2. Keep AST fix path behind feature flag / fallback only.
3. Maintain current regression guards.

Deliverable:

- `--fix` works on files with comments for migrated rules.

## Phase 2: Rule Safety Classification

1. Assign safety level to each fixable rule.
2. Set conservative defaults (`Safe` only).
3. Add CLI output fields for skipped/unsafe/conflicting fixes.

Deliverable:

- predictable fix behavior with explicit safety controls.

## Phase 3: Dialect Completion

1. Validate migrated rules on all dialect fixtures.
2. Add dialect capability checks where token semantics differ.
3. Expand patch support for dialect-specific syntax cases.

Deliverable:

- cross-dialect safe fix baseline.

## Phase 4: Templating-Aware Fixing

1. Introduce raw/rendered slice mapping in fix planner.
2. Block fixes in unstable template-derived slices.
3. Add template fixture coverage.

Deliverable:

- safe fixes on templated SQL where mapping is reliable.

## Phase 5: AST Fix De-emphasis

1. Default to patch-based engine for all supported fix rules.
2. Keep AST full-render rewrites as opt-in experimental path only.
3. Remove global comment-file skip once parity is reached.

Deliverable:

- comment-safe default `--fix` behavior.

## Validation Commands

Core checks:

```bash
just fmt-rust
just lint-rust
just test-cli
just test-core
```

Targeted checks (to add/update):

```bash
cargo test -p flowscope-cli fix::tests::comments_are_not_globally_skipped -- --nocapture
cargo test -p flowscope-cli --test lint_cli -- --nocapture
cargo test -p flowscope-core --test linter -- --nocapture
```

Future required suites:

- conflict-resolution unit tests,
- comment-preservation golden tests,
- per-dialect fix fixtures,
- template map round-trip tests,
- idempotence tests (`fix` twice => no further diff).

## Risks and Mitigations

1. Offset drift from sequential edits.
- Mitigation: apply sorted edits from end-to-start; invariant tests.

2. Rule interaction conflicts.
- Mitigation: overlap rejection + isolation groups + deterministic ordering.

3. Dialect edge-case regressions.
- Mitigation: per-dialect fixture matrix and capability gating.

4. Template mapping ambiguity.
- Mitigation: reject unmappable edits; report skip reason.

5. Performance overhead from extra validation.
- Mitigation: cache parse/token artifacts and lint results by hash.

## Success Criteria

1. `--lint --fix` no longer globally skips comment-containing files.
2. `Safe` fixes preserve comments byte-for-byte.
3. No increase in parse-error regressions from fix application.
4. Deterministic output independent of thread scheduling.
5. CLI and LSP produce equivalent fix results.

## Implementation Notes for FlowScope

- Reuse existing linter diagnostics pipeline where possible.
- Add fix planner as a standalone module called from `flowscope-cli` and any future API endpoints.
- Keep current regression guard semantics as mandatory write gate.
- Document user-facing safety model in CLI README once Phase 2 lands.
