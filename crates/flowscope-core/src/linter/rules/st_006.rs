//! LINT_ST_006: Structure column order.
//!
//! SQLFluff ST06 parity: prefer wildcards first, then simple column references
//! and casts, before complex expressions (aggregates, window functions, etc.)
//! in SELECT projection lists.
//!
//! The rule only applies to order-insensitive SELECTs: it skips INSERT, MERGE,
//! CREATE TABLE AS, and SELECTs participating in UNION/set operations (where
//! column position is semantically significant).

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{
    Expr, GroupByExpr, Query, Select, SelectItem, SetExpr, Statement, TableFactor,
};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct StructureColumnOrder;

impl LintRule for StructureColumnOrder {
    fn code(&self) -> &'static str {
        issue_codes::LINT_ST_006
    }

    fn name(&self) -> &'static str {
        "Structure column order"
    }

    fn description(&self) -> &'static str {
        "Select wildcards then simple targets before calculations and aggregates."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut violations_info: Vec<ViolationInfo> = Vec::new();
        visit_order_safe_selects(statement, &mut |select| {
            if let Some(info) = check_select_order(select) {
                violations_info.push(info);
            }
        });

        let mut autofix_candidates = st006_autofix_candidates_for_context(ctx, &violations_info);
        autofix_candidates.sort_by_key(|candidate| candidate.span.start);
        let candidates_align = autofix_candidates.len() == violations_info.len();

        violations_info
            .iter()
            .enumerate()
            .map(|(index, _info)| {
                let mut issue = Issue::info(
                    issue_codes::LINT_ST_006,
                    "Prefer simple columns before complex expressions in SELECT.",
                )
                .with_statement(ctx.statement_index);
                if candidates_align {
                    let candidate = &autofix_candidates[index];
                    issue = issue.with_span(candidate.span).with_autofix_edits(
                        IssueAutofixApplicability::Safe,
                        candidate.edits.clone(),
                    );
                }
                issue
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Band-based item classification
// ---------------------------------------------------------------------------

/// SQLFluff ST06 classifies items into ordered bands:
///   Band 0: wildcards (`*`, `table.*`)
///   Band 1: simple columns, literals, standalone casts
///   Band 2: complex expressions (aggregates, window functions, arithmetic, etc.)
fn item_band(item: &SelectItem) -> u8 {
    match item {
        SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _) => 0,
        SelectItem::UnnamedExpr(expr) => expr_band(expr),
        SelectItem::ExprWithAlias { expr, .. } => expr_band(expr),
    }
}

fn expr_band(expr: &Expr) -> u8 {
    match expr {
        // Simple identifiers.
        Expr::Identifier(_) | Expr::CompoundIdentifier(_) => 1,
        // Literal values.
        Expr::Value(_) => 1,
        // Standalone CAST expressions: `CAST(x AS type)` or `x::type`.
        Expr::Cast { expr: inner, .. } => {
            let inner_band = expr_band(inner);
            if inner_band <= 1 {
                1
            } else {
                2
            }
        }
        // CAST as a function call: `cast(b)` parsed as Function.
        Expr::Function(f) if is_cast_function(f) => 1,
        // Nested/parenthesized expression — unwrap.
        Expr::Nested(inner) => expr_band(inner),
        // Everything else: functions, binary ops, window functions, etc.
        _ => 2,
    }
}

/// Check if a function call is a CAST function (e.g. `cast(b)` parsed as Function).
fn is_cast_function(f: &sqlparser::ast::Function) -> bool {
    use sqlparser::ast::ObjectNamePart;
    f.name
        .0
        .last()
        .and_then(ObjectNamePart::as_ident)
        .is_some_and(|ident| ident.value.eq_ignore_ascii_case("CAST"))
}

// ---------------------------------------------------------------------------
// Violation detection
// ---------------------------------------------------------------------------

struct ViolationInfo {
    /// The band assignments for each projection item.
    bands: Vec<u8>,
    /// Whether the SELECT has implicit column references (GROUP BY 1, 2).
    has_implicit_refs: bool,
}

/// Check if a SELECT's projection ordering violates band order.
/// Returns `Some(ViolationInfo)` if there is a violation.
fn check_select_order(select: &Select) -> Option<ViolationInfo> {
    if select.projection.len() < 2 {
        return None;
    }

    let bands: Vec<u8> = select.projection.iter().map(item_band).collect();

    // A violation exists when any item has a lower band than a preceding item.
    let mut max_band = 0u8;
    let mut violated = false;
    for &band in &bands {
        if band < max_band {
            violated = true;
            break;
        }
        max_band = max_band.max(band);
    }

    if !violated {
        return None;
    }

    let has_implicit_refs = has_implicit_column_references(select);

    Some(ViolationInfo {
        bands,
        has_implicit_refs,
    })
}

/// Returns true if the SELECT uses positional (numeric) column references
/// in GROUP BY or ORDER BY (e.g. `GROUP BY 1, 2`).
fn has_implicit_column_references(select: &Select) -> bool {
    if let GroupByExpr::Expressions(exprs, _) = &select.group_by {
        for expr in exprs {
            if matches!(expr, Expr::Value(v) if matches!(v.value, sqlparser::ast::Value::Number(_, _)))
            {
                return true;
            }
        }
    }

    for sort in &select.sort_by {
        if matches!(&sort.expr, Expr::Value(v) if matches!(v.value, sqlparser::ast::Value::Number(_, _)))
        {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Context-aware SELECT visitor (skips order-sensitive contexts)
// ---------------------------------------------------------------------------

/// Visit only SELECTs where column order is NOT semantically significant.
/// Skips INSERT, MERGE, CREATE TABLE AS, and set operations (UNION, etc.).
fn visit_order_safe_selects<F: FnMut(&Select)>(statement: &Statement, visitor: &mut F) {
    match statement {
        Statement::Query(query) => visit_query_selects(query, visitor, false),
        // INSERT: column order matters — skip entirely.
        Statement::Insert(_) => {}
        // MERGE: column order matters — skip entirely.
        Statement::Merge { .. } => {}
        // CREATE TABLE AS SELECT: column order matters — skip entirely.
        Statement::CreateTable(create) => {
            if create.query.is_some() {
                // CREATE TABLE AS SELECT — skip.
            }
            // Regular CREATE TABLE without AS SELECT — nothing relevant to visit.
        }
        Statement::CreateView { query, .. } => {
            visit_query_selects(query, visitor, false);
        }
        Statement::Update {
            table,
            from,
            selection,
            ..
        } => {
            // Visit subqueries in table/from/where but not the statement columns.
            visit_table_factor_selects(&table.relation, visitor);
            for join in &table.joins {
                visit_table_factor_selects(&join.relation, visitor);
            }
            if let Some(from) = from {
                match from {
                    sqlparser::ast::UpdateTableFromKind::BeforeSet(tables)
                    | sqlparser::ast::UpdateTableFromKind::AfterSet(tables) => {
                        for t in tables {
                            visit_table_factor_selects(&t.relation, visitor);
                            for j in &t.joins {
                                visit_table_factor_selects(&j.relation, visitor);
                            }
                        }
                    }
                }
            }
            if let Some(sel) = selection {
                visit_expr_selects(sel, visitor);
            }
        }
        _ => {}
    }
}

fn visit_query_selects<F: FnMut(&Select)>(query: &Query, visitor: &mut F, in_set_operation: bool) {
    // Visit CTE definitions — these may or may not be order-sensitive.
    // A CTE is order-sensitive if referenced in a set operation whose leaf
    // SELECTs use wildcards (SELECT *), since reordering the CTE projection
    // would change the set operation result. When the set operation's leaf
    // SELECTs use explicit columns (SELECT a, b), CTE order is irrelevant.
    if let Some(with) = &query.with {
        let body_is_set = matches!(query.body.as_ref(), SetExpr::SetOperation { .. });
        let cte_order_matters = body_is_set && set_expr_has_wildcard_select(&query.body);
        for cte in &with.cte_tables {
            visit_query_selects(&cte.query, visitor, cte_order_matters);
        }
    }

    visit_set_expr_selects(&query.body, visitor, in_set_operation);
}

fn visit_set_expr_selects<F: FnMut(&Select)>(
    set_expr: &SetExpr,
    visitor: &mut F,
    in_set_operation: bool,
) {
    match set_expr {
        SetExpr::Select(select) => {
            if in_set_operation {
                // In a set operation, column order is semantically significant.
                // Skip both this SELECT and its FROM subqueries, since subquery
                // column order feeds into the set operation result.
                return;
            }
            visitor(select);
            // Visit subqueries in FROM clause.
            for table in &select.from {
                visit_table_factor_selects(&table.relation, visitor);
                for join in &table.joins {
                    visit_table_factor_selects(&join.relation, visitor);
                }
            }
            // Visit subqueries in WHERE, etc.
            if let Some(sel) = &select.selection {
                visit_expr_selects(sel, visitor);
            }
        }
        SetExpr::Query(query) => visit_query_selects(query, visitor, in_set_operation),
        SetExpr::SetOperation { left, right, .. } => {
            // Both sides of a set operation are order-sensitive.
            visit_set_expr_selects(left, visitor, true);
            visit_set_expr_selects(right, visitor, true);
        }
        _ => {}
    }
}

fn visit_table_factor_selects<F: FnMut(&Select)>(table_factor: &TableFactor, visitor: &mut F) {
    match table_factor {
        TableFactor::Derived { subquery, .. } => {
            visit_query_selects(subquery, visitor, false);
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            visit_table_factor_selects(&table_with_joins.relation, visitor);
            for join in &table_with_joins.joins {
                visit_table_factor_selects(&join.relation, visitor);
            }
        }
        _ => {}
    }
}

fn visit_expr_selects<F: FnMut(&Select)>(expr: &Expr, visitor: &mut F) {
    match expr {
        Expr::Subquery(query)
        | Expr::Exists {
            subquery: query, ..
        } => visit_query_selects(query, visitor, false),
        Expr::InSubquery {
            expr: inner,
            subquery,
            ..
        } => {
            visit_expr_selects(inner, visitor);
            visit_query_selects(subquery, visitor, false);
        }
        Expr::BinaryOp { left, right, .. } => {
            visit_expr_selects(left, visitor);
            visit_expr_selects(right, visitor);
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::Cast { expr: inner, .. } => visit_expr_selects(inner, visitor),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(op) = operand {
                visit_expr_selects(op, visitor);
            }
            for when in conditions {
                visit_expr_selects(&when.condition, visitor);
                visit_expr_selects(&when.result, visitor);
            }
            if let Some(e) = else_result {
                visit_expr_selects(e, visitor);
            }
        }
        _ => {}
    }
}

/// Returns true if any leaf SELECT in a set expression uses a wildcard
/// (`SELECT *` or `SELECT table.*`). When a set operation uses wildcards,
/// the column order of referenced CTEs/subqueries is semantically significant.
fn set_expr_has_wildcard_select(set_expr: &SetExpr) -> bool {
    match set_expr {
        SetExpr::Select(select) => select
            .projection
            .iter()
            .any(|item| matches!(item, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(_, _))),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_has_wildcard_select(left) || set_expr_has_wildcard_select(right)
        }
        SetExpr::Query(query) => set_expr_has_wildcard_select(&query.body),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Autofix
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PositionedToken {
    token: Token,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct SelectProjectionSegment {
    item_spans: Vec<Span>,
}

#[derive(Clone, Debug)]
struct St006AutofixCandidate {
    span: Span,
    edits: Vec<IssuePatchEdit>,
}

fn st006_autofix_candidates_for_context(
    ctx: &LintContext,
    violations: &[ViolationInfo],
) -> Vec<St006AutofixCandidate> {
    let from_document_tokens = ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        let mut positioned = Vec::new();
        for token in tokens {
            let (start, end) = token_with_span_offsets(ctx.sql, token)?;
            if start < ctx.statement_range.start || end > ctx.statement_range.end {
                continue;
            }
            positioned.push(PositionedToken {
                token: token.token.clone(),
                start,
                end,
            });
        }
        Some(positioned)
    });

    let tokens = if let Some(tokens) = from_document_tokens {
        tokens
    } else {
        let Some(tokens) = tokenize_with_spans(ctx.statement_sql(), ctx.dialect()) else {
            return Vec::new();
        };

        let mut positioned = Vec::new();
        for token in &tokens {
            let Some((start, end)) = token_with_span_offsets(ctx.statement_sql(), token) else {
                continue;
            };
            positioned.push(PositionedToken {
                token: token.token.clone(),
                start: ctx.statement_range.start + start,
                end: ctx.statement_range.start + end,
            });
        }
        positioned
    };

    let segments = select_projection_segments(&tokens);

    // We need to match segments to violations. Since we skip some SELECTs
    // (set operations, INSERT, etc.), the segments from token scanning may
    // not 1:1 align with violations. Use positional matching.
    // If counts don't match, bail out.
    if segments.len() < violations.len() {
        return Vec::new();
    }

    // Find segments that have violations by scanning all segments and matching
    // against the violation bands. For each segment, compute its bands from
    // token-based item count and see if it matches a violation.
    let mut candidates = Vec::new();
    let mut violation_idx = 0;
    for segment in &segments {
        if violation_idx >= violations.len() {
            break;
        }
        let violation = &violations[violation_idx];
        if segment.item_spans.len() != violation.bands.len() {
            continue;
        }

        // Skip autofix if implicit column references exist.
        if violation.has_implicit_refs {
            violation_idx += 1;
            continue;
        }

        if let Some(candidate) =
            projection_reorder_candidate_by_band(ctx.sql, &tokens, segment, &violation.bands)
        {
            candidates.push(candidate);
        }
        violation_idx += 1;
    }

    candidates
}

fn select_projection_segments(tokens: &[PositionedToken]) -> Vec<SelectProjectionSegment> {
    let significant_positions: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (!is_trivia(&token.token)).then_some(index))
        .collect();
    if significant_positions.is_empty() {
        return Vec::new();
    }

    let mut depths = vec![0usize; significant_positions.len()];
    let mut depth = 0usize;
    for (position, token_index) in significant_positions.iter().copied().enumerate() {
        depths[position] = depth;
        match tokens[token_index].token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    let mut segments = Vec::new();
    for position in 0..significant_positions.len() {
        let token = &tokens[significant_positions[position]].token;
        if !token_word_equals(token, "SELECT") {
            continue;
        }

        let base_depth = depths[position];
        let Some(projection_start) = projection_start_after_select(
            tokens,
            &significant_positions,
            &depths,
            position + 1,
            base_depth,
        ) else {
            continue;
        };
        let Some(from_position) = from_position_for_select(
            tokens,
            &significant_positions,
            &depths,
            projection_start,
            base_depth,
        ) else {
            continue;
        };
        if from_position <= projection_start {
            continue;
        }

        let item_spans = projection_item_spans(
            tokens,
            &significant_positions,
            &depths,
            projection_start,
            from_position,
            base_depth,
        );
        if item_spans.is_empty() {
            continue;
        }

        segments.push(SelectProjectionSegment { item_spans });
    }

    segments
}

fn projection_start_after_select(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    depths: &[usize],
    mut position: usize,
    base_depth: usize,
) -> Option<usize> {
    while position < significant_positions.len() {
        if depths[position] != base_depth {
            return Some(position);
        }

        let token = &tokens[significant_positions[position]].token;
        if token_word_equals(token, "DISTINCT")
            || token_word_equals(token, "ALL")
            || token_word_equals(token, "DISTINCTROW")
        {
            position += 1;
            continue;
        }
        return Some(position);
    }

    None
}

fn from_position_for_select(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    depths: &[usize],
    start_position: usize,
    base_depth: usize,
) -> Option<usize> {
    (start_position..significant_positions.len()).find(|&position| {
        depths[position] == base_depth
            && token_word_equals(&tokens[significant_positions[position]].token, "FROM")
    })
}

fn projection_item_spans(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    depths: &[usize],
    start_position: usize,
    from_position: usize,
    base_depth: usize,
) -> Vec<Span> {
    if start_position >= from_position {
        return Vec::new();
    }

    let mut spans = Vec::new();
    let mut item_start = start_position;

    for position in start_position..from_position {
        let token = &tokens[significant_positions[position]].token;
        if depths[position] == base_depth && matches!(token, Token::Comma) {
            if item_start < position {
                if let Some(span) =
                    span_from_positions(tokens, significant_positions, item_start, position - 1)
                {
                    spans.push(span);
                }
            }
            item_start = position + 1;
        }
    }

    if item_start < from_position {
        if let Some(span) =
            span_from_positions(tokens, significant_positions, item_start, from_position - 1)
        {
            spans.push(span);
        }
    }

    spans
}

fn span_from_positions(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    start_position: usize,
    end_position: usize,
) -> Option<Span> {
    if end_position < start_position {
        return None;
    }

    let start = tokens[*significant_positions.get(start_position)?].start;
    let end = tokens[*significant_positions.get(end_position)?].end;
    (start < end).then_some(Span::new(start, end))
}

/// Reorder projection items by band, preserving relative order within each band.
fn projection_reorder_candidate_by_band(
    sql: &str,
    tokens: &[PositionedToken],
    segment: &SelectProjectionSegment,
    bands: &[u8],
) -> Option<St006AutofixCandidate> {
    if segment.item_spans.len() != bands.len() {
        return None;
    }

    let replace_span = Span::new(
        segment.item_spans.first()?.start,
        segment.item_spans.last()?.end,
    );
    if replace_span.start >= replace_span.end || replace_span.end > sql.len() {
        return None;
    }
    if segment_contains_comment(tokens, replace_span) {
        return None;
    }

    let mut item_texts = Vec::with_capacity(segment.item_spans.len());
    for span in &segment.item_spans {
        if span.start >= span.end || span.end > sql.len() {
            return None;
        }
        let text = sql[span.start..span.end].trim();
        if text.is_empty() || text.contains('\n') || text.contains('\r') {
            return None;
        }
        item_texts.push(text.to_string());
    }

    // Stable sort by band — items with same band keep their relative order.
    let mut indexed: Vec<(usize, u8, &str)> = item_texts
        .iter()
        .enumerate()
        .zip(bands.iter())
        .map(|((i, text), &band)| (i, band, text.as_str()))
        .collect();
    indexed.sort_by_key(|&(i, band, _)| (band, i));

    let reordered: Vec<&str> = indexed.iter().map(|&(_, _, text)| text).collect();
    let replacement = reordered.join(", ");
    if replacement.is_empty() || replacement == sql[replace_span.start..replace_span.end].trim() {
        return None;
    }

    Some(St006AutofixCandidate {
        span: replace_span,
        edits: vec![IssuePatchEdit::new(replace_span, replacement)],
    })
}

fn segment_contains_comment(tokens: &[PositionedToken], span: Span) -> bool {
    tokens
        .iter()
        .any(|token| token.start >= span.start && token.end <= span.end && is_comment(&token.token))
}

// ---------------------------------------------------------------------------
// Token utilities
// ---------------------------------------------------------------------------

fn tokenize_with_spans(sql: &str, dialect: Dialect) -> Option<Vec<TokenWithSpan>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    tokenizer.tokenize_with_location().ok()
}

fn token_with_span_offsets(sql: &str, token: &TokenWithSpan) -> Option<(usize, usize)> {
    let start = line_col_to_offset(
        sql,
        token.span.start.line as usize,
        token.span.start.column as usize,
    )?;
    let end = line_col_to_offset(
        sql,
        token.span.end.line as usize,
        token.span.end.column as usize,
    )?;
    Some((start, end))
}

fn line_col_to_offset(sql: &str, line: usize, column: usize) -> Option<usize> {
    if line == 0 || column == 0 {
        return None;
    }

    let mut current_line = 1usize;
    let mut current_col = 1usize;
    for (offset, ch) in sql.char_indices() {
        if current_line == line && current_col == column {
            return Some(offset);
        }
        if ch == '\n' {
            current_line += 1;
            current_col = 1;
        } else {
            current_col += 1;
        }
    }
    if current_line == line && current_col == column {
        return Some(sql.len());
    }
    None
}

fn token_word_equals(token: &Token, expected_upper: &str) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case(expected_upper))
}

fn is_trivia(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(
            Whitespace::Space
                | Whitespace::Newline
                | Whitespace::Tab
                | Whitespace::SingleLineComment { .. }
                | Whitespace::MultiLineComment(_)
        )
    )
}

fn is_comment(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = StructureColumnOrder;
        statements
            .iter()
            .enumerate()
            .flat_map(|(index, statement)| {
                rule.check(
                    statement,
                    &LintContext {
                        sql,
                        statement_range: 0..sql.len(),
                        statement_index: index,
                    },
                )
            })
            .collect()
    }

    fn apply_edits(sql: &str, edits: &[IssuePatchEdit]) -> String {
        let mut output = sql.to_string();
        let mut ordered = edits.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|edit| edit.span.start);

        for edit in ordered.into_iter().rev() {
            output.replace_range(edit.span.start..edit.span.end, &edit.replacement);
        }

        output
    }

    // --- Pass cases from SQLFluff ST06 fixture ---

    #[test]
    fn pass_select_statement_order() {
        // a (simple), cast(b) (cast), c (simple) — all in band 1, no violation.
        let issues = run("SELECT a, cast(b as int) as b, c FROM x");
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_union_statements_ignored() {
        let sql = "SELECT a + b as c, d FROM table_a UNION ALL SELECT c, d FROM table_b";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_insert_statements_ignored() {
        let sql = "\
INSERT INTO example_schema.example_table
(id, example_column, rank_asc, rank_desc)
SELECT
    id,
    CASE WHEN col_a IN('a', 'b', 'c') THEN col_a END AS example_column,
    rank_asc,
    rank_desc
FROM another_schema.another_table";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_insert_statement_with_cte_ignored() {
        let sql = "\
INSERT INTO my_table
WITH my_cte AS (SELECT * FROM t1)
SELECT MAX(field1), field2
FROM t1";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_merge_statements_ignored() {
        let sql = "\
MERGE INTO t
USING
(
    SELECT
        DATE_TRUNC('DAY', end_time) AS time_day,
        b
    FROM u
) AS u ON (a = b)
WHEN MATCHED THEN
UPDATE SET a = b
WHEN NOT MATCHED THEN
INSERT (b) VALUES (c)";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_merge_statement_with_cte_ignored() {
        let sql = "\
MERGE INTO t
USING
(
    WITH my_cte AS (SELECT * FROM t1)
    SELECT MAX(field1), field2
    FROM t1
) AS u ON (a = b)
WHEN MATCHED THEN
UPDATE SET a = b
WHEN NOT MATCHED THEN
INSERT (b) VALUES (c)";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_create_table_as_select_with_cte_ignored() {
        let sql = "\
CREATE TABLE new_table AS (
  WITH my_cte AS (SELECT * FROM t1)
  SELECT MAX(field1), field2
  FROM t1
)";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn pass_cte_used_in_set() {
        let sql = "\
WITH T1 AS (
  SELECT
    'a'::varchar AS A,
    1::bigint AS B
),
T2 AS (
  SELECT
    CASE WHEN COL > 1 THEN 'x' ELSE 'y' END AS A,
    COL AS B
  FROM T
)
SELECT * FROM T1
UNION ALL
SELECT * FROM T2";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn fail_cte_used_in_set_with_explicit_columns() {
        // When the set operation uses explicit column lists (not SELECT *),
        // CTE projection order is irrelevant and ST06 should still apply.
        let sql = "\
WITH T1 AS (
  SELECT
    'a'::varchar AS A,
    1::bigint AS B
),
T2 AS (
  SELECT
    CASE WHEN COL > 1 THEN 'x' ELSE 'y' END AS A,
    COL AS B
  FROM T
)
SELECT A, B FROM T1
UNION ALL
SELECT A, B FROM T2";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_006);
    }

    #[test]
    fn pass_subquery_used_in_set() {
        let sql = "\
SELECT * FROM (SELECT 'a'::varchar AS A, 1::bigint AS B)
UNION ALL
SELECT * FROM (SELECT CASE WHEN COL > 1 THEN 'x' ELSE 'y' END AS A, COL AS B FROM T)";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    // --- Fail cases from SQLFluff ST06 fixture ---

    #[test]
    fn fail_select_statement_order_1() {
        // a (band 1), row_number() over (...) (band 2), b (band 1) → violation.
        let sql = "SELECT a, row_number() over (partition by id order by date) as y, b FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_006);
    }

    #[test]
    fn fail_select_statement_order_2() {
        // row_number() (band 2), * (band 0), cast(b) (band 1) → violation.
        let sql = "SELECT row_number() over (partition by id order by date) as y, *, cast(b as int) as b_int FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_select_statement_order_3() {
        // row_number() (band 2), cast(b) (band 1), * (band 0) → violation.
        let sql = "SELECT row_number() over (partition by id order by date) as y, cast(b as int) as b_int, * FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_select_statement_order_4() {
        // row_number() (band 2), b::int (band 1), * (band 0) → violation.
        let sql = "SELECT row_number() over (partition by id order by date) as y, b::int, * FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_select_statement_order_5() {
        // row_number() (band 2), * (band 0), 2::int + 4 (band 2), cast(b) (band 1) → violation.
        let sql = "SELECT row_number() over (partition by id order by date) as y, *, 2::int + 4 as sum, cast(b) as c FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    // --- Autofix tests ---

    #[test]
    fn autofix_reorder_simple_before_complex() {
        let sql = "SELECT a + 1, a FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0].autofix.as_ref().expect("expected ST006 autofix");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "SELECT a, a + 1 FROM t");
    }

    #[test]
    fn autofix_reorder_wildcard_first() {
        let sql = "SELECT row_number() over (partition by id order by date) as y, *, cast(b as int) as b_int FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0].autofix.as_ref().expect("expected ST006 autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "SELECT *, cast(b as int) as b_int, row_number() over (partition by id order by date) as y FROM x");
    }

    #[test]
    fn autofix_reorder_with_casts() {
        let sql = "SELECT row_number() over (partition by id order by date) as y, b::int, * FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0].autofix.as_ref().expect("expected ST006 autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(
            fixed,
            "SELECT *, b::int, row_number() over (partition by id order by date) as y FROM x"
        );
    }

    #[test]
    fn autofix_fail_order_5_complex() {
        // row_number() (2), * (0), 2::int + 4 (2), cast(b) (1)
        // Expected: * (0), cast(b) (1), row_number() (2), 2::int + 4 (2)
        let sql = "SELECT row_number() over (partition by id order by date) as y, *, 2::int + 4 as sum, cast(b) as c FROM x";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0].autofix.as_ref().expect("expected ST006 autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "SELECT *, cast(b) as c, row_number() over (partition by id order by date) as y, 2::int + 4 as sum FROM x");
    }

    #[test]
    fn no_autofix_with_implicit_column_references() {
        let sql =
            "SELECT DATE_TRUNC('DAY', end_time) AS time_day, b_field FROM table_name GROUP BY 1, 2";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "should not autofix when implicit column references exist"
        );
    }

    #[test]
    fn autofix_explicit_column_references() {
        let sql = "SELECT DATE_TRUNC('DAY', end_time) AS time_day, b_field FROM table_name GROUP BY time_day, b_field";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0].autofix.as_ref().expect("expected ST006 autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "SELECT b_field, DATE_TRUNC('DAY', end_time) AS time_day FROM table_name GROUP BY time_day, b_field");
    }

    #[test]
    fn fail_cte_used_in_select_not_set() {
        // CTE used in a regular SELECT (not UNION), so ST06 should apply to the CTE.
        let sql = "\
WITH T2 AS (
  SELECT
    CASE WHEN COL > 1 THEN 'x' ELSE 'y' END AS A,
    COL AS B
  FROM T
)
SELECT * FROM T2";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn comment_in_projection_blocks_safe_autofix_metadata() {
        let sql = "SELECT a + 1 /*keep*/, a FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "comment-bearing projection should not receive ST006 safe patch metadata"
        );
    }

    // --- Existing tests ---

    #[test]
    fn does_not_flag_when_simple_target_starts_projection() {
        let issues = run("SELECT a, a + 1 FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_simple_target_after_complex() {
        // SQLFluff ST06 flags `b` (band 1) appearing after `a + 1` (band 2).
        let issues = run("SELECT a, a + 1, b FROM t");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn does_not_flag_when_alias_wraps_simple_identifier() {
        let issues = run("SELECT a AS first_a, b FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_in_nested_select_scopes() {
        let issues = run("SELECT * FROM (SELECT a + 1, a FROM t) AS sub");
        assert_eq!(issues.len(), 1);
    }
}
