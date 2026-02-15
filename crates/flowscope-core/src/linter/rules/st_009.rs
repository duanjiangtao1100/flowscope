//! LINT_ST_009: Reversed JOIN condition ordering.
//!
//! Detect predicates where the newly joined relation appears on the left side
//! and prior relation on the right side (e.g. `o.user_id = u.id`).

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{BinaryOperator, Expr, Spanned, Statement, TableFactor};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

use super::semantic_helpers::{
    join_on_expr, table_factor_reference_name, visit_selects_in_statement,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreferredFirstTableInJoinClause {
    Earlier,
    Later,
}

impl PreferredFirstTableInJoinClause {
    fn from_config(config: &LintConfig) -> Self {
        match config
            .rule_option_str(
                issue_codes::LINT_ST_009,
                "preferred_first_table_in_join_clause",
            )
            .unwrap_or("earlier")
            .to_ascii_lowercase()
            .as_str()
        {
            "later" => Self::Later,
            _ => Self::Earlier,
        }
    }

    fn left_source<'a>(self, current: &'a str, previous: &'a str) -> &'a str {
        match self {
            Self::Earlier => current,
            Self::Later => previous,
        }
    }

    fn right_source<'a>(self, current: &'a str, previous: &'a str) -> &'a str {
        match self {
            Self::Earlier => previous,
            Self::Later => current,
        }
    }
}

pub struct StructureJoinConditionOrder {
    preferred_first_table: PreferredFirstTableInJoinClause,
}

impl StructureJoinConditionOrder {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            preferred_first_table: PreferredFirstTableInJoinClause::from_config(config),
        }
    }
}

impl Default for StructureJoinConditionOrder {
    fn default() -> Self {
        Self {
            preferred_first_table: PreferredFirstTableInJoinClause::Earlier,
        }
    }
}

impl LintRule for StructureJoinConditionOrder {
    fn code(&self) -> &'static str {
        issue_codes::LINT_ST_009
    }

    fn name(&self) -> &'static str {
        "Structure join condition order"
    }

    fn description(&self) -> &'static str {
        "Joins should list the table referenced earlier/later first."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        visit_selects_in_statement(statement, &mut |select| {
            for table in &select.from {
                let mut seen_sources: Vec<String> = Vec::new();
                check_table_factor_joins(
                    &table.relation,
                    &table.joins,
                    &mut seen_sources,
                    self.preferred_first_table,
                    ctx,
                    &mut issues,
                );
            }
        });

        issues
    }
}

fn check_table_factor_joins(
    relation: &TableFactor,
    joins: &[sqlparser::ast::Join],
    seen_sources: &mut Vec<String>,
    preference: PreferredFirstTableInJoinClause,
    ctx: &LintContext,
    issues: &mut Vec<Issue>,
) {
    // For NestedJoin, recurse into the inner table_with_joins.
    if let TableFactor::NestedJoin {
        table_with_joins, ..
    } = relation
    {
        check_table_factor_joins(
            &table_with_joins.relation,
            &table_with_joins.joins,
            seen_sources,
            preference,
            ctx,
            issues,
        );
    } else if let Some(base) = table_factor_reference_name(relation) {
        seen_sources.push(base);
    }

    for join in joins {
        // Recurse into nested join relations on the right side.
        if let TableFactor::NestedJoin {
            table_with_joins, ..
        } = &join.relation
        {
            check_table_factor_joins(
                &table_with_joins.relation,
                &table_with_joins.joins,
                seen_sources,
                preference,
                ctx,
                issues,
            );
        }

        let join_name = table_factor_reference_name(&join.relation);
        let previous_source = seen_sources.last().cloned();

        if let (Some(current), Some(previous), Some(on_expr)) = (
            join_name.as_ref(),
            previous_source.as_ref(),
            join_on_expr(&join.join_operator),
        ) {
            let left = preference.left_source(current, previous);
            let right = preference.right_source(current, previous);
            if has_join_pair(on_expr, left, right) {
                let mut issue = Issue::info(
                    issue_codes::LINT_ST_009,
                    "Join condition ordering appears inconsistent with configured preference.",
                )
                .with_statement(ctx.statement_index);

                if let Some((span, replacement)) =
                    join_condition_autofix(ctx, on_expr, left, right)
                {
                    issue = issue.with_span(span).with_autofix_edits(
                        IssueAutofixApplicability::Safe,
                        vec![IssuePatchEdit::new(span, replacement)],
                    );
                }

                issues.push(issue);
            }
        }

        if let Some(name) = join_name {
            seen_sources.push(name);
        }
    }
}

fn is_comparison_operator(op: &BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Lt
            | BinaryOperator::Gt
            | BinaryOperator::LtEq
            | BinaryOperator::GtEq
            | BinaryOperator::Spaceship
    )
}

fn has_join_pair(expr: &Expr, left_source_name: &str, right_source_name: &str) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let direct = if is_comparison_operator(op) {
                if let (Some(left_prefix), Some(right_prefix)) =
                    (expr_qualified_prefix(left), expr_qualified_prefix(right))
                {
                    left_prefix == left_source_name && right_prefix == right_source_name
                } else {
                    false
                }
            } else {
                false
            };

            direct
                || has_join_pair(left, left_source_name, right_source_name)
                || has_join_pair(right, left_source_name, right_source_name)
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::Cast { expr: inner, .. } => {
            has_join_pair(inner, left_source_name, right_source_name)
        }
        Expr::InList { expr, list, .. } => {
            has_join_pair(expr, left_source_name, right_source_name)
                || list
                    .iter()
                    .any(|item| has_join_pair(item, left_source_name, right_source_name))
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            has_join_pair(expr, left_source_name, right_source_name)
                || has_join_pair(low, left_source_name, right_source_name)
                || has_join_pair(high, left_source_name, right_source_name)
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            operand
                .as_ref()
                .is_some_and(|operand| has_join_pair(operand, left_source_name, right_source_name))
                || conditions.iter().any(|when| {
                    has_join_pair(&when.condition, left_source_name, right_source_name)
                        || has_join_pair(&when.result, left_source_name, right_source_name)
                })
                || else_result.as_ref().is_some_and(|otherwise| {
                    has_join_pair(otherwise, left_source_name, right_source_name)
                })
        }
        _ => false,
    }
}

fn join_condition_autofix(
    ctx: &LintContext,
    on_expr: &Expr,
    current_source: &str,
    previous_source: &str,
) -> Option<(Span, String)> {
    let mut rewritten = on_expr.clone();
    rewrite_reversed_join_pairs(&mut rewritten, current_source, previous_source);
    if exprs_equivalent(on_expr, &rewritten) {
        return None;
    }

    let (start, end) = expr_statement_offsets(ctx, on_expr)?;
    let span = ctx.span_from_statement_offset(start, end);
    if span_contains_comment(ctx, span) {
        return None;
    }

    Some((span, rewritten.to_string()))
}

fn flip_comparison_operator(op: &BinaryOperator) -> Option<BinaryOperator> {
    match op {
        BinaryOperator::Eq | BinaryOperator::NotEq | BinaryOperator::Spaceship => Some(op.clone()),
        BinaryOperator::Lt => Some(BinaryOperator::Gt),
        BinaryOperator::Gt => Some(BinaryOperator::Lt),
        BinaryOperator::LtEq => Some(BinaryOperator::GtEq),
        BinaryOperator::GtEq => Some(BinaryOperator::LtEq),
        _ => None,
    }
}

fn rewrite_reversed_join_pairs(expr: &mut Expr, current_source: &str, previous_source: &str) {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            if is_comparison_operator(op) {
                let left_prefix = expr_qualified_prefix(left);
                let right_prefix = expr_qualified_prefix(right);
                if left_prefix.as_deref() == Some(current_source)
                    && right_prefix.as_deref() == Some(previous_source)
                {
                    std::mem::swap(left, right);
                    if let Some(flipped) = flip_comparison_operator(op) {
                        *op = flipped;
                    }
                }
            }

            rewrite_reversed_join_pairs(left, current_source, previous_source);
            rewrite_reversed_join_pairs(right, current_source, previous_source);
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsUnknown(inner)
        | Expr::IsNotUnknown(inner)
        | Expr::Cast { expr: inner, .. } => {
            rewrite_reversed_join_pairs(inner, current_source, previous_source)
        }
        Expr::InList {
            expr: target, list, ..
        } => {
            rewrite_reversed_join_pairs(target, current_source, previous_source);
            for item in list {
                rewrite_reversed_join_pairs(item, current_source, previous_source);
            }
        }
        Expr::Between {
            expr: target,
            low,
            high,
            ..
        } => {
            rewrite_reversed_join_pairs(target, current_source, previous_source);
            rewrite_reversed_join_pairs(low, current_source, previous_source);
            rewrite_reversed_join_pairs(high, current_source, previous_source);
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand) = operand {
                rewrite_reversed_join_pairs(operand, current_source, previous_source);
            }
            for case_when in conditions {
                rewrite_reversed_join_pairs(
                    &mut case_when.condition,
                    current_source,
                    previous_source,
                );
                rewrite_reversed_join_pairs(&mut case_when.result, current_source, previous_source);
            }
            if let Some(else_result) = else_result {
                rewrite_reversed_join_pairs(else_result, current_source, previous_source);
            }
        }
        _ => {}
    }
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

fn exprs_equivalent(left: &Expr, right: &Expr) -> bool {
    format!("{left}") == format!("{right}")
}

fn expr_qualified_prefix(expr: &Expr) -> Option<String> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() > 1 => {
            parts.first().map(|ident| ident.value.to_ascii_uppercase())
        }
        Expr::Nested(inner)
        | Expr::UnaryOp { expr: inner, .. }
        | Expr::Cast { expr: inner, .. } => expr_qualified_prefix(inner),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::{IssueAutofixApplicability, IssuePatchEdit};

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = StructureJoinConditionOrder::default();
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

    // --- Edge cases adopted from sqlfluff ST09 ---

    #[test]
    fn allows_queries_without_joins() {
        let issues = run("select * from foo");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_expected_source_order_in_join_condition() {
        let issues = run("select foo.a, bar.b from foo left join bar on foo.a = bar.a");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_reversed_source_order_in_join_condition() {
        let issues = run("select foo.a, bar.b from foo left join bar on bar.a = foo.a");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_009);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected ST009 core autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        let fixed = apply_edits(
            "select foo.a, bar.b from foo left join bar on bar.a = foo.a",
            &autofix.edits,
        );
        assert_eq!(
            fixed,
            "select foo.a, bar.b from foo left join bar on foo.a = bar.a"
        );
    }

    #[test]
    fn allows_unqualified_reference_side() {
        let issues = run("select foo.a, bar.b from foo left join bar on bar.b = a");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_multiple_reversed_subconditions() {
        let issues = run(
            "select foo.a, foo.b, bar.c from foo left join bar on bar.a = foo.a and bar.b = foo.b",
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn later_preference_flags_earlier_on_left_side() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "structure.join_condition_order".to_string(),
                serde_json::json!({"preferred_first_table_in_join_clause": "later"}),
            )]),
        };
        let rule = StructureJoinConditionOrder::from_config(&config);
        let sql = "select foo.a, bar.b from foo left join bar on foo.a = bar.a";
        let statements = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_009);
    }

    #[test]
    fn comment_in_join_condition_blocks_safe_autofix_metadata() {
        let sql = "select foo.a, bar.b from foo left join bar on bar.a /*keep*/ = foo.a";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "comment-bearing join condition should not emit ST009 safe patch metadata"
        );
    }

    #[test]
    fn flags_reversed_non_equality_comparison_operators() {
        // SQLFluff: test_fail_later_table_first_multiple_comparison_operators
        let sql = "select foo.a, bar.b from foo left join bar on bar.a != foo.a and bar.b > foo.b and bar.c <= foo.c";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_009);
    }

    #[test]
    fn flags_reversed_join_inside_bracketed_from() {
        // SQLFluff: test_fail_later_table_first_brackets_after_from
        let sql = "select foo.a, bar.b from (foo left join bar on bar.a = foo.a)";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_009);
    }

    #[test]
    fn flags_spaceship_operator_reversed() {
        // SQLFluff: test_fail_sparksql_lt_eq_gt_operator
        let sql = "SELECT bt.test FROM base_table AS bt INNER JOIN second_table AS st ON st.test <=> bt.test";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_009);
    }
}
