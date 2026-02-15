//! LINT_ST_002: Structure simple case.
//!
//! SQLFluff ST02 parity: prefer simple `CASE <expr> WHEN ...` form when all
//! searched-case predicates compare the same operand for equality.

use crate::linter::rule::{LintContext, LintRule};
use crate::linter::visit;
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{BinaryOperator, Expr, Spanned, Statement};
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
            let Some(rewrite) = simple_case_rewrite_info(expr) else {
                return;
            };

            let mut issue = Issue::info(
                issue_codes::LINT_ST_002,
                "CASE expression may be simplified to simple CASE form.",
            )
            .with_statement(ctx.statement_index);

            if let Some((span, edits)) = simple_case_autofix(ctx, expr, &rewrite) {
                issue = issue
                    .with_span(span)
                    .with_autofix_edits(IssueAutofixApplicability::Safe, edits);
            }

            issues.push(issue);
        });

        issues
    }
}

#[derive(Clone, Copy)]
enum OperandSide {
    Left,
    Right,
}

#[derive(Clone)]
struct SimpleCaseRewriteInfo {
    operand_expr: Expr,
    conditions: Vec<RewriteConditionMatch>,
}

fn simple_case_rewrite_info(expr: &Expr) -> Option<SimpleCaseRewriteInfo> {
    let Expr::Case {
        operand: None,
        conditions,
        ..
    } = expr
    else {
        return None;
    };

    if conditions.len() < 2 {
        return None;
    }

    let mut common_operand: Option<Expr> = None;
    let mut rewrite_conditions = Vec::with_capacity(conditions.len());

    for case_when in conditions {
        let rewrite = split_case_when_equality(&case_when.condition, common_operand.as_ref())?;
        if common_operand.is_none() {
            common_operand = Some(rewrite.operand_expr.clone());
        }
        rewrite_conditions.push(rewrite);
    }

    Some(SimpleCaseRewriteInfo {
        operand_expr: common_operand?,
        conditions: rewrite_conditions,
    })
}

fn split_case_when_equality(
    condition: &Expr,
    expected_operand: Option<&Expr>,
) -> Option<RewriteConditionMatch> {
    let Expr::BinaryOp { left, op, right } = condition else {
        return None;
    };

    if *op != BinaryOperator::Eq {
        return None;
    }

    if let Some(expected) = expected_operand {
        if exprs_equivalent(left, expected) {
            return Some(RewriteConditionMatch {
                operand_expr: left.as_ref().clone(),
                value_expr: right.as_ref().clone(),
                operand_side: OperandSide::Left,
            });
        }
        if exprs_equivalent(right, expected) {
            return Some(RewriteConditionMatch {
                operand_expr: right.as_ref().clone(),
                value_expr: left.as_ref().clone(),
                operand_side: OperandSide::Right,
            });
        }
        return None;
    }

    if simple_case_operand_candidate(left) {
        return Some(RewriteConditionMatch {
            operand_expr: left.as_ref().clone(),
            value_expr: right.as_ref().clone(),
            operand_side: OperandSide::Left,
        });
    }
    if simple_case_operand_candidate(right) {
        return Some(RewriteConditionMatch {
            operand_expr: right.as_ref().clone(),
            value_expr: left.as_ref().clone(),
            operand_side: OperandSide::Right,
        });
    }

    None
}

#[derive(Clone)]
struct RewriteConditionMatch {
    operand_expr: Expr,
    value_expr: Expr,
    operand_side: OperandSide,
}

fn simple_case_autofix(
    ctx: &LintContext,
    expr: &Expr,
    rewrite: &SimpleCaseRewriteInfo,
) -> Option<(Span, Vec<IssuePatchEdit>)> {
    let Expr::Case {
        operand: None,
        conditions,
        ..
    } = expr
    else {
        return None;
    };

    if conditions.len() != rewrite.conditions.len() || conditions.is_empty() {
        return None;
    }

    let (expr_start, expr_end) = expr_statement_offsets(ctx, expr)?;
    let expr_span = ctx.span_from_statement_offset(expr_start, expr_end);
    if span_contains_comment(ctx, expr_span) {
        return None;
    }

    let (operand_start, operand_end) = expr_statement_offsets(ctx, &rewrite.operand_expr)?;
    let operand_text = ctx
        .statement_sql()
        .get(operand_start..operand_end)?
        .to_string();

    let (first_condition_start, _) = expr_statement_offsets(ctx, &conditions[0].condition)?;
    let case_keyword_end = expr_start + "CASE".len();
    if case_keyword_end > first_condition_start {
        return None;
    }

    let mut edits = Vec::with_capacity(1 + rewrite.conditions.len());
    edits.push(IssuePatchEdit::new(
        ctx.span_from_statement_offset(case_keyword_end, first_condition_start),
        format!(" {operand_text} WHEN "),
    ));

    for (case_when, rewrite_condition) in conditions.iter().zip(&rewrite.conditions) {
        let (condition_start, condition_end) = expr_statement_offsets(ctx, &case_when.condition)?;
        let (value_start, value_end) = expr_statement_offsets(ctx, &rewrite_condition.value_expr)?;

        match rewrite_condition.operand_side {
            OperandSide::Left => {
                if condition_start >= value_start {
                    return None;
                }
                edits.push(IssuePatchEdit::new(
                    ctx.span_from_statement_offset(condition_start, value_start),
                    "",
                ));
            }
            OperandSide::Right => {
                if value_end >= condition_end {
                    return None;
                }
                edits.push(IssuePatchEdit::new(
                    ctx.span_from_statement_offset(value_end, condition_end),
                    "",
                ));
            }
        }
    }

    Some((expr_span, edits))
}

fn simple_case_operand_candidate(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

fn exprs_equivalent(left: &Expr, right: &Expr) -> bool {
    format!("{left}") == format!("{right}")
}

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

    // --- Edge cases adopted from sqlfluff ST02 ---

    #[test]
    fn flags_simple_case_candidate() {
        let sql = "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' END FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_002);
    }

    #[test]
    fn flags_reversed_operand_comparisons() {
        let sql = "SELECT CASE WHEN 1 = x THEN 'a' WHEN 2 = x THEN 'b' END FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn does_not_flag_when_operands_differ() {
        let sql = "SELECT CASE WHEN x = 1 THEN 'a' WHEN y = 2 THEN 'b' END FROM t";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn does_not_flag_simple_case_form() {
        let sql = "SELECT CASE x WHEN 1 THEN 'a' WHEN 2 THEN 'b' END FROM t";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn does_not_flag_single_when_case() {
        let sql = "SELECT CASE WHEN x = 1 THEN 'a' END FROM t";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn emits_safe_autofix_for_simple_case_rewrite() {
        let sql = "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' END FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected ST002 core autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 3);

        let fixed = apply_edits(sql, &autofix.edits);
        assert_eq!(
            fixed,
            "SELECT CASE x WHEN 1 THEN 'a' WHEN 2 THEN 'b' END FROM t"
        );
    }

    #[test]
    fn comment_in_case_blocks_safe_autofix_metadata() {
        let sql = "SELECT CASE WHEN x = 1 /*keep*/ THEN 'a' WHEN x = 2 THEN 'b' END FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "comment-bearing CASE expression should not receive ST002 safe patch metadata"
        );
    }
}
