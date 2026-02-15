//! LINT_ST_002: Unnecessary CASE statement.
//!
//! SQLFluff ST02 parity: detect CASE expressions that can be replaced by
//! simpler forms such as `COALESCE(...)`, `NOT COALESCE(...)`, or a plain
//! column reference.
//!
//! Detectable patterns:
//!   1. `CASE WHEN cond THEN TRUE  ELSE FALSE END` → `COALESCE(cond, FALSE)`
//!   2. `CASE WHEN cond THEN FALSE ELSE TRUE  END` → `NOT COALESCE(cond, FALSE)`
//!   3. `CASE WHEN x IS NULL     THEN y ELSE x END` → `COALESCE(x, y)`
//!   4. `CASE WHEN x IS NOT NULL THEN x ELSE y END` → `COALESCE(x, y)`
//!   5. `CASE WHEN x IS NULL     THEN NULL ELSE x END` → `x`
//!   6. `CASE WHEN x IS NOT NULL THEN x ELSE NULL END` → `x`
//!   7. `CASE WHEN x IS NOT NULL THEN x END`          → `x`

use crate::linter::rule::{LintContext, LintRule};
use crate::linter::visit;
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{Expr, Spanned, Statement, Value};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct StructureSimpleCase;

impl LintRule for StructureSimpleCase {
    fn code(&self) -> &'static str {
        issue_codes::LINT_ST_002
    }

    fn name(&self) -> &'static str {
        "Structure simple case"
    }

    fn description(&self) -> &'static str {
        "Unnecessary 'CASE' statement."
    }

    fn check(&self, stmt: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        visit::visit_expressions(stmt, &mut |expr| {
            let Some(rewrite) = classify_unnecessary_case(expr) else {
                return;
            };

            let mut issue = Issue::info(
                issue_codes::LINT_ST_002,
                "Unnecessary CASE statement. Use COALESCE function or simple column reference.",
            )
            .with_statement(ctx.statement_index);

            if let Some((span, edits)) = build_autofix(ctx, expr, &rewrite) {
                issue = issue
                    .with_span(span)
                    .with_autofix_edits(IssueAutofixApplicability::Safe, edits);
            }

            issues.push(issue);
        });

        issues
    }
}

// ---------------------------------------------------------------------------
// Rewrite classification
// ---------------------------------------------------------------------------

/// The kind of simplification that can be applied.
#[derive(Debug, Clone)]
enum UnnecessaryCaseKind {
    /// `CASE WHEN cond THEN TRUE ELSE FALSE END` → `COALESCE(cond, FALSE)`
    BoolCoalesce { condition_text: String },
    /// `CASE WHEN cond THEN FALSE ELSE TRUE END` → `NOT COALESCE(cond, FALSE)`
    BoolCoalesceNegated { condition_text: String },
    /// `CASE WHEN x IS [NOT] NULL THEN a ELSE b END` → `COALESCE(x, y)`
    NullCoalesce {
        checked_text: String,
        fallback_text: String,
    },
    /// `CASE WHEN x IS [NOT] NULL THEN x [ELSE NULL] END` → `x`
    ColumnIdentity { column_text: String },
}

/// Classify the CASE expression if it is an unnecessary pattern.
fn classify_unnecessary_case(expr: &Expr) -> Option<UnnecessaryCaseKind> {
    let Expr::Case {
        operand: None,
        conditions,
        else_result,
        ..
    } = expr
    else {
        return None;
    };

    // Only single-WHEN case expressions can be simplified.
    if conditions.len() != 1 {
        return None;
    }

    let when = &conditions[0];
    let condition = &when.condition;
    let result = &when.result;

    // -----------------------------------------------------------------------
    // Pattern group 1: boolean CASE WHEN cond THEN TRUE/FALSE ELSE FALSE/TRUE
    // -----------------------------------------------------------------------
    if let Some(result_bool) = expr_bool_value(result) {
        if let Some(else_bool) = else_result.as_deref().and_then(expr_bool_value) {
            // TRUE/FALSE or FALSE/TRUE — other combos don't simplify.
            if result_bool && !else_bool {
                // CASE WHEN cond THEN TRUE ELSE FALSE END → coalesce(cond, false)
                return Some(UnnecessaryCaseKind::BoolCoalesce {
                    condition_text: format!("{condition}"),
                });
            } else if !result_bool && else_bool {
                // CASE WHEN cond THEN FALSE ELSE TRUE END → not coalesce(cond, false)
                return Some(UnnecessaryCaseKind::BoolCoalesceNegated {
                    condition_text: format!("{condition}"),
                });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Pattern group 2: NULL-check simplifications
    // -----------------------------------------------------------------------
    // CASE WHEN x IS NULL THEN ... ELSE ... END
    if let Expr::IsNull(checked_expr) = condition {
        return classify_null_check_case(checked_expr, result, else_result.as_deref(), true);
    }

    // CASE WHEN x IS NOT NULL THEN ... ELSE ... END
    if let Expr::IsNotNull(checked_expr) = condition {
        return classify_null_check_case(checked_expr, result, else_result.as_deref(), false);
    }

    None
}

/// Classify a CASE with IS NULL / IS NOT NULL condition.
fn classify_null_check_case(
    checked_expr: &Expr,
    then_result: &Expr,
    else_result: Option<&Expr>,
    is_null_check: bool,
) -> Option<UnnecessaryCaseKind> {
    let checked_text = format!("{checked_expr}");
    let then_text = format!("{then_result}");
    let else_text = else_result.map(|e| format!("{e}"));

    if is_null_check {
        // CASE WHEN x IS NULL THEN ... ELSE x END
        if let Some(ref else_t) = else_text {
            if else_t == &checked_text {
                // CASE WHEN x IS NULL THEN result ELSE x END
                if is_null_expr(then_result) {
                    // CASE WHEN x IS NULL THEN NULL ELSE x END → x
                    return Some(UnnecessaryCaseKind::ColumnIdentity {
                        column_text: checked_text,
                    });
                }
                // CASE WHEN x IS NULL THEN y ELSE x END → COALESCE(x, y)
                return Some(UnnecessaryCaseKind::NullCoalesce {
                    checked_text,
                    fallback_text: then_text,
                });
            }
        }
    } else {
        // CASE WHEN x IS NOT NULL THEN ... ELSE ... END
        if then_text == checked_text {
            match &else_text {
                Some(et) if is_null_text(et) => {
                    // CASE WHEN x IS NOT NULL THEN x ELSE NULL END → x
                    return Some(UnnecessaryCaseKind::ColumnIdentity {
                        column_text: checked_text,
                    });
                }
                None => {
                    // CASE WHEN x IS NOT NULL THEN x END → x
                    return Some(UnnecessaryCaseKind::ColumnIdentity {
                        column_text: checked_text,
                    });
                }
                Some(fallback) => {
                    // CASE WHEN x IS NOT NULL THEN x ELSE y END → COALESCE(x, y)
                    return Some(UnnecessaryCaseKind::NullCoalesce {
                        checked_text,
                        fallback_text: fallback.clone(),
                    });
                }
            }
        }
    }

    None
}

fn expr_bool_value(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Boolean(b) => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

fn is_null_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(v) if matches!(v.value, Value::Null))
}

fn is_null_text(s: &str) -> bool {
    s.eq_ignore_ascii_case("NULL")
}

// ---------------------------------------------------------------------------
// Autofix
// ---------------------------------------------------------------------------

fn build_autofix(
    ctx: &LintContext,
    expr: &Expr,
    rewrite: &UnnecessaryCaseKind,
) -> Option<(Span, Vec<IssuePatchEdit>)> {
    let (expr_start, expr_end) = expr_statement_offsets(ctx, expr)?;
    let expr_span = ctx.span_from_statement_offset(expr_start, expr_end);

    if span_contains_comment(ctx, expr_span) {
        return None;
    }

    let replacement = match rewrite {
        UnnecessaryCaseKind::BoolCoalesce { condition_text } => {
            format!("coalesce({condition_text}, false)")
        }
        UnnecessaryCaseKind::BoolCoalesceNegated { condition_text } => {
            format!("not coalesce({condition_text}, false)")
        }
        UnnecessaryCaseKind::NullCoalesce {
            checked_text,
            fallback_text,
        } => {
            format!("coalesce({checked_text}, {fallback_text})")
        }
        UnnecessaryCaseKind::ColumnIdentity { column_text } => column_text.clone(),
    };

    Some((expr_span, vec![IssuePatchEdit::new(expr_span, replacement)]))
}

// ---------------------------------------------------------------------------
// Span and offset utilities
// ---------------------------------------------------------------------------

fn expr_statement_offsets(ctx: &LintContext, expr: &Expr) -> Option<(usize, usize)> {
    if let Some((start, end)) = expr_span_offsets(ctx.statement_sql(), expr) {
        return Some((start, end));
    }

    let (start, end) = expr_span_offsets(ctx.sql, expr)?;
    if start < ctx.statement_range.start || end > ctx.statement_range.end {
        return None;
    }

    Some((
        start - ctx.statement_range.start,
        end - ctx.statement_range.start,
    ))
}

fn expr_span_offsets(sql: &str, expr: &Expr) -> Option<(usize, usize)> {
    let span = expr.span();
    if span.start.line == 0 || span.start.column == 0 || span.end.line == 0 || span.end.column == 0
    {
        return None;
    }

    let start = line_col_to_offset(sql, span.start.line as usize, span.start.column as usize)?;
    let end = line_col_to_offset(sql, span.end.line as usize, span.end.column as usize)?;
    (end >= start).then_some((start, end))
}

fn span_contains_comment(ctx: &LintContext, span: Span) -> bool {
    let from_document_tokens = ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }
        Some(tokens.iter().any(|token| {
            let Some((start, end)) = token_with_span_offsets(ctx.sql, token) else {
                return false;
            };
            start >= span.start && end <= span.end && is_comment_token(&token.token)
        }))
    });

    if let Some(has_comment) = from_document_tokens {
        return has_comment;
    }

    let Some(tokens) = tokenize_statement_with_spans(ctx.statement_sql(), ctx.dialect()) else {
        return false;
    };
    let statement_span = Span::new(
        span.start.saturating_sub(ctx.statement_range.start),
        span.end.saturating_sub(ctx.statement_range.start),
    );
    tokens.iter().any(|token| {
        let Some((start, end)) = token_with_span_offsets(ctx.statement_sql(), token) else {
            return false;
        };
        start >= statement_span.start && end <= statement_span.end && is_comment_token(&token.token)
    })
}

fn tokenize_statement_with_spans(
    sql: &str,
    dialect: crate::types::Dialect,
) -> Option<Vec<TokenWithSpan>> {
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
    let mut line_start = 0usize;

    for (idx, ch) in sql.char_indices() {
        if current_line == line {
            break;
        }
        if ch == '\n' {
            current_line += 1;
            line_start = idx + ch.len_utf8();
        }
    }
    if current_line != line {
        return None;
    }

    let mut current_column = 1usize;
    for (rel_idx, ch) in sql[line_start..].char_indices() {
        if current_column == column {
            return Some(line_start + rel_idx);
        }
        if ch == '\n' {
            return None;
        }
        current_column += 1;
    }

    if current_column == column {
        return Some(sql.len());
    }

    None
}

fn is_comment_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::{IssueAutofixApplicability, IssuePatchEdit};

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = StructureSimpleCase;
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

    // --- Pass cases from SQLFluff ST02 fixture ---

    #[test]
    fn pass_case_cannot_be_reduced_1() {
        let sql = "select fab > 0 as is_fab from fancy_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_case_cannot_be_reduced_2() {
        let sql = "select case when fab > 0 then true end as is_fab from fancy_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_case_cannot_be_reduced_3() {
        let sql = "select case when fab is not null then false end as is_fab from fancy_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_case_cannot_be_reduced_4() {
        let sql = "select case when fab > 0 then true else true end as is_fab from fancy_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_case_cannot_be_reduced_5() {
        let sql =
            "select case when fab <> 0 then 'just a string' end as fab_category from fancy_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_case_cannot_be_reduced_6() {
        let sql = "select case when fab <> 0 then true when fab < 0 then 'not a bool' end as fab_category from fancy_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_single_when_is_null_then_bar() {
        let sql = "select foo, case when bar is null then bar else '123' end as test from baz";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_is_not_null_then_literal() {
        let sql = "select foo, case when bar is not null then '123' else bar end as test from baz";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_multiple_when_is_not_null() {
        let sql = "select foo, case when bar is not null then '123' when foo is not null then '456' else bar end as test from baz";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_compound_condition() {
        let sql = "select foo, case when bar is not null and abs(foo) > 0 then '123' else bar end as test from baz";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_window_lead_is_null() {
        let sql = "SELECT dv_runid, CASE WHEN LEAD(dv_startdateutc) OVER (PARTITION BY rowid ORDER BY dv_startdateutc) IS NULL THEN 1 ELSE 0 END AS loadstate FROM d";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_coalesce_is_null() {
        let sql = "select field_1, field_2, field_3, case when coalesce(field_2, field_3) is null then 1 else 0 end as field_4 from my_table";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_submitted_timestamp() {
        let sql = "SELECT CASE WHEN item.submitted_timestamp IS NOT NULL THEN item.sitting_id END";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn pass_array_accessor_snowflake() {
        let sql = "SELECT CASE WHEN genres[0] IS NULL THEN 'x' ELSE genres END AS g FROM table_t";
        assert!(run(sql).is_empty());
    }

    // --- Fail cases from SQLFluff ST02 fixture ---

    #[test]
    fn fail_unnecessary_case_bool_true_false() {
        let sql = "select case when fab > 0 then true else false end as is_fab from fancy_table";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_002);
    }

    #[test]
    fn fail_unnecessary_case_bool_false_true() {
        let sql = "select case when fab > 0 then false else true end as is_fab from fancy_table";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_unnecessary_case_bool_compound_condition() {
        let sql = "select case when fab > 0 and tot > 0 then true else false end as is_fab from fancy_table";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_unnecessary_case_is_null_coalesce() {
        let sql = "select foo, case when bar is null then '123' else bar end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_unnecessary_case_is_not_null_coalesce() {
        let sql = "select foo, case when bar is not null then bar else '123' end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_unnecessary_case_is_null_identity_null_else() {
        let sql = "select foo, case when bar is null then null else bar end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_unnecessary_case_is_not_null_identity_else_null() {
        let sql = "select foo, case when bar is not null then bar else null end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_unnecessary_case_is_not_null_identity_no_else() {
        let sql = "select foo, case when bar is not null then bar end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn fail_is_null_then_false_else_true() {
        let sql = "select case when perks.perk is null then false else true end as perk_redeemed from subscriptions_xf";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    // --- Autofix tests ---

    #[test]
    fn autofix_bool_true_false() {
        let sql = "select case when fab > 0 then true else false end as is_fab from fancy_table";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(
            fixed,
            "select coalesce(fab > 0, false) as is_fab from fancy_table"
        );
    }

    #[test]
    fn autofix_bool_false_true() {
        let sql = "select case when fab > 0 then false else true end as is_fab from fancy_table";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(
            fixed,
            "select not coalesce(fab > 0, false) as is_fab from fancy_table"
        );
    }

    #[test]
    fn autofix_is_null_coalesce() {
        let sql = "select foo, case when bar is null then '123' else bar end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "select foo, coalesce(bar, '123') as test from baz");
    }

    #[test]
    fn autofix_is_not_null_coalesce() {
        let sql = "select foo, case when bar is not null then bar else '123' end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "select foo, coalesce(bar, '123') as test from baz");
    }

    #[test]
    fn autofix_is_null_then_null_identity() {
        let sql = "select foo, case when bar is null then null else bar end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "select foo, bar as test from baz");
    }

    #[test]
    fn autofix_is_not_null_identity_no_else() {
        let sql = "select foo, case when bar is not null then bar end as test from baz";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(fixed, "select foo, bar as test from baz");
    }

    #[test]
    fn comment_in_case_blocks_safe_autofix() {
        let sql =
            "select case when fab > 0 /*keep*/ then true else false end as is_fab from fancy_table";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "comment-bearing CASE expression should not receive safe patch metadata"
        );
    }
}
