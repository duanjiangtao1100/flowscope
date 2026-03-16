# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-03-16

### Added

- **Oracle dialect** support across CLI (`-d oracle`), core engine, and web app UI
- Autofix metadata types, `applyEdits` utility, and lint provenance fields

### Changed

- **Bumped sqlparser from 0.59 to 0.61** — migrates all AST pattern matches to the new tuple-variant API where `Statement`, `TableConstraint`, `ColumnOption`, and `MergeAction` variants now wrap dedicated structs
- Adapted to `ConnectBy` becoming `Vec<ConnectByKind>`, `TableAlias` gaining an `explicit` field, and `TableFactor::Derived` gaining a `sample` field

## [0.4.1] - 2026-03-03

### Improved

- Added linter documentation to README files across the monorepo (core, CLI, export crates)
- Aligned npm package versions with Cargo workspace version (was 0.3.1, now 0.4.1)
- Rebuilt WASM artifacts from current Rust source

## [0.4.0] - 2026-03-02

### Added

#### SQL Linter Engine (flowscope-core)
- **Full SQL linting engine** with 60+ rules targeting SQLFluff parity
  - **Aliasing rules** (AL001–AL009): alias expression style, column alias quoting, unused aliases, duplicate column names, alias length limits, force-enable aliasing
  - **Ambiguity rules** (AM001–AM009): DISTINCT with GROUP BY, UNION type handling, ORDER BY column ordinals, ambiguous column counts, bare JOINs, set-column mismatches, implicit cross joins, limit without ORDER BY
  - **Capitalisation rules** (CP001–CP005): keyword, identifier, function name, literal, and type-annotation casing with consistent/upper/lower modes and `ignore_words_regex` support
  - **Convention rules** (CV001–CV012): operator style, COALESCE usage, trailing commas, COUNT row-style, IS NULL comparison, statement terminators, unnecessary brackets, LEFT JOIN preference, block quotes, quoted literals, CAST shorthand, implicit join detection
  - **Jinja rules** (JJ001): template tag detection with trim-marker parity
  - **Layout rules** (LT001–LT015): trailing whitespace, indentation, operator placement, comma position, long lines, function spacing, bracket placement, CTE newlines, SELECT modifiers, set operators, end-of-file newlines, start-of-file blanks, keyword line position, blank line limits
  - **Reference rules** (RF001–RF006): keyword references, qualified wildcards, single-table qualifications, keyword aliases, identifier quoting policies
  - **Structure rules** (ST001–ST012): ELSE/THEN on new lines, simple CASE, unused CTEs, nested CASE, subquery-to-CTE, column ordering, USING joins, DISTINCT parentheses, join condition order, constant predicates, unused joins, consecutive semicolons
  - **T-SQL rules** (TQ001–TQ003): SP_ prefix, SET NOCOUNT, batch separators
- **Rule configuration system** supporting SQLFluff `.sqlfluff` config format with per-rule options (e.g., `capitalisation_policy`, `line_position`, `max_line_length`, `allow_scalar`)
- **Dialect-aware detection** adapting rule behavior for PostgreSQL, BigQuery, Snowflake, Redshift, SparkSQL, MSSQL, and others
- **Autofix metadata** on issues with `Safe`/`Unsafe` applicability markers and patch edits

#### CLI (flowscope-cli)
- `--lint` flag for SQL linting with JSON, compact, and human-readable output formats
- `--fix` flag for automatic SQL fixing with safe-only default and `--legacy-ast-fixes` for additional rewrites
- `--fix-only` mode for applying fixes without re-linting
- `--exclude-rules` for disabling specific lint rules
- `--rule-configs-json` for passing rule configuration as JSON
- `--show-fixes` to display applied fix details
- `--jobs` for parallel multi-file lint/fix processing
- `--no-respect-gitignore` for including gitignored files
- Fix engine with iterative convergence loop, overlap recovery, and incremental rule evaluation budgets
- Performance-tuned large-SQL handling with capped fix passes and targeted LT02 cleanup

#### CI
- GitHub Actions CI workflow for lint, test, and parity validation

### Improved

#### Core Engine (flowscope-core)
- Migrated all lint rules from regex to AST/tokenizer-driven detection for accuracy and performance
- Shared document token stream across rules to avoid redundant tokenization
- Token-span-based issue reporting for precise editor navigation

#### Web App (app/)
- Integrated linter into the web app: lint is now enabled by default in the analysis worker
- Updated WASM bindings to include lint API surface (`LintIssue`, `LintRequest`, `LintConfig` types)
- Lint-aware issues panel with updated filtering
- Updated mascot to purple-headed duck and added favicon, removed beta badge

## [0.3.1] - 2026-01-23

### Fixed

#### CLI (flowscope-cli)
- Enable `serve` feature by default so `cargo install flowscope-cli` includes the web UI server
- Fix rust-embed asset path for embedded web UI (was incorrectly pointing to workspace root)

## [0.3.0] - 2026-01-22

### Added

#### Core Engine (flowscope-core)
- **Jinja/dbt templating support**: MiniJinja-based preprocessing for dbt projects
  - Built-in dbt macros: `ref()`, `source()`, `config()`, `var()`, `is_incremental()`
  - RelationEmulator for dbt Relation object attribute access (`.schema`, `.identifier`)
  - `this` global variable and `execute` flag for templates
  - Custom macro passthrough stubs for graceful handling
- **COPY statement lineage**: Track source/target tables in COPY/COPY INTO (PostgreSQL, Snowflake)
- **ALTER TABLE RENAME lineage**: Track table renames as dataflow edges
- **UNLOAD statement lineage**: Track source tables from Redshift UNLOAD statements
- **Lateral column alias support**: Resolve aliases in same SELECT list (BigQuery, Snowflake, DuckDB, etc.)
- **Backward column inference**: Infer columns for SELECT * without schema from downstream usage
- Type inference for SQL expressions with comprehensive type checking
- New `TYPE_MISMATCH` warning code for detecting incompatible type comparisons and operations
- Schema-aware column type lookup - column references now resolve types from provided schema metadata
- CTE column type propagation to outer queries
- Dialect-aware type compatibility rules (e.g., Boolean/Integer comparison allowed in MySQL but not PostgreSQL)
- NULL comparison anti-pattern detection (`= NULL` warns to use `IS NULL` instead)

#### Completion API
- Smart function completions with signature metadata (params, return types, categories)
- Context-aware scoring: boost aggregates in GROUP BY, window functions in OVER clauses
- Lateral column alias extraction with proper scope isolation
- Type-aware column scoring in comparison contexts
- Dialect-aware keyword parsing using sqlparser tokenizer
- CASE expression type inference from THEN/ELSE branches

#### CLI (flowscope-cli)
- `--template jinja|dbt` flag for templated SQL preprocessing
- `--template-var KEY=VALUE` for template variable injection
- `--metadata-url` for live database schema introspection (PostgreSQL, MySQL, SQLite)
- `--metadata-schema` for schema filtering during introspection
- **Serve mode**: Run FlowScope as a local HTTP server with embedded web UI
  - `--serve` flag to start HTTP server with embedded React app
  - `--port <PORT>` to specify server port (default: 3000)
  - `--watch <DIR>` for directories to watch for SQL files (repeatable)
  - `--open` to auto-open browser on startup
  - REST API endpoints: `/api/analyze`, `/api/completion`, `/api/files`, `/api/export/:format`
  - File watcher with 100ms debounce for automatic reload on changes
  - Assets embedded at compile time via rust-embed for single-binary deployment

#### React Package (@pondpilot/flowscope-react)
- Web workers for graph/matrix/layout computations (improved UI responsiveness)
- LayoutProgressIndicator component for visual layout feedback
- Debug flags (GRAPH_DEBUG, LAYOUT_DEBUG) for performance diagnostics

#### Web App (app/)
- Template mode selector for dbt/Jinja SQL preprocessing in the toolbar
- Issue-to-editor navigation: click issues to jump to source location
- Issues tab filtering: filter by severity, error code, and file
- Stats popover: complexity dots trigger dropdown with table/column/join counts
- Clear analysis cache option in project menu
- Bundled "dbt Jaffle Shop" demo project showcasing ref/source/config/var
- Backend adapter pattern for REST/WASM detection (supports serve mode)
- Read-only mode for files loaded from CLI serve backend
- Schema display from database introspection in serve mode

### Changed

#### Core Engine (flowscope-core)
- Unified type system: `CanonicalType` replaces internal `SqlType` enum with broader coverage (Time, Binary, Json, Array)
- `OutputColumn.data_type` now populated with inferred types for SELECT expressions
- Type checking now accepts dialect parameter for dialect-specific rules

### Fixed

#### Core Engine (flowscope-core)
- dbt model cross-statement linking with proper case normalization for Snowflake
- DDL-seeded schema preservation (schemas no longer overwritten by later queries)
- UTF-8 safety in `should_show_for_cursor` when cursor offset is mid-character

### Known Limitations

#### Type Inference
- **Schema-unaware type checking**: TYPE_MISMATCH warnings only detect mismatches between literals, CASTs, and known function return types. Column type mismatches (e.g., `WHERE users.id = users.email` where `id` is INTEGER and `email` is TEXT) are not detected because expression type inference does not yet resolve column types from schema metadata.
- **No expression spans**: TYPE_MISMATCH warnings include the statement index but not precise source spans for editor integration. This is because sqlparser's expression AST nodes don't include span information by default.

## [0.2.0] - 2026-01-18

### Highlights
- First public release of the FlowScope Rust + WASM + TypeScript stack
- Multi-dialect SQL parsing with table/column lineage, schema validation, and editor-friendly spans
- Export tooling for Mermaid, JSON, HTML, CSV bundles, and XLSX across Rust and WASM
- React components + CLI for lineage visualization and data export workflows
- CTE and derived table definitions now include spans for editor navigation
- Export downloads in React normalize byte buffers for reliable Blob creation

### Changed

#### WASM Module (flowscope-wasm)
- **Breaking**: Changed error code from `REQUEST_PARSE_ERROR` to `INVALID_REQUEST` for JSON parse/validation errors in `analyze_sql_json()`. Consumers matching on the old error code should update their error handling.

### Fixed

#### Core Engine (flowscope-core)
- Fixed potential panic in `extract_qualifier` when cursor offset lands on invalid UTF-8 boundary
- Fixed early-return bug in completion logic that incorrectly suppressed completions when schema metadata lacked column info but query context (CTEs/subqueries) had valid columns
- Fixed potential integer overflow in completion item scoring by using saturating arithmetic
- Added spans for CTE and derived table definition nodes to support editor navigation

#### Exporter (flowscope-export)
- Bundle reserved keyword list inside the crate for publish-time builds

#### React Package (@pondpilot/flowscope-react)
- Fixed ZIP/XLSX downloads by normalizing export byte buffers for Blob creation

### Improved

#### Core Engine (flowscope-core)
- Added named constants for completion scoring values to improve code maintainability
- Added `Debug` derive to `QualifierResolution` for easier debugging
- Added comprehensive unit tests for string helper functions (`extract_last_identifier`, `extract_qualifier`) and qualifier resolution logic

## [0.1.0] - 2025-11-21

### Added

#### Core Engine (flowscope-core)
- SQL parsing with sqlparser-rs for multiple dialects
- Table-level lineage extraction from SELECT, JOIN, CTE, INSERT, CTAS, UNION
- Cross-statement lineage tracking via GlobalLineage
- Schema metadata support for table validation
- UNKNOWN_TABLE warning when tables not in provided schema
- Structured issue reporting with severity levels (error, warning, info)
- Graceful degradation - partial results on parse failures

#### WASM Module (flowscope-wasm)
- WebAssembly bindings for browser usage
- JSON-in/JSON-out API via `analyze_sql_json()`
- Legacy `analyze_sql()` function for backwards compatibility
- Version info via `get_version()`

#### TypeScript Package (@pondpilot/flowscope-core)
- WASM loader with `initWasm()` function
- Type-safe `analyzeSql()` function
- Complete TypeScript type definitions
- JSDoc documentation on all public types

#### Supported Dialects
- Generic SQL
- PostgreSQL
- Snowflake
- BigQuery

#### Supported Statements
- SELECT (with aliases, subqueries)
- JOIN (INNER, LEFT, RIGHT, FULL, CROSS)
- WITH / CTE (multiple, nested references)
- INSERT INTO ... SELECT
- CREATE TABLE AS SELECT
- UNION / UNION ALL / INTERSECT / EXCEPT

#### Documentation
- User guides (quickstart, schema metadata, error handling)
- Dialect coverage matrix
- API documentation (rustdoc, TypeDoc)
- Test fixtures for all dialects

#### Testing
- 45+ Rust unit tests
- 11 TypeScript type tests
- Test fixtures per dialect (generic, postgres, snowflake, bigquery)
- CI/CD with GitHub Actions

### Known Limitations
- Column-level lineage not yet implemented (planned for v0.2.0)
- Recursive CTEs generate warning, lineage may be incomplete
- UPDATE, DELETE, MERGE statements not yet supported
