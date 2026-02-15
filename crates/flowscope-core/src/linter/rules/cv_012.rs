//! LINT_CV_012: JOIN condition convention.
//!
//! Plain `JOIN` clauses without ON/USING should use explicit join predicates,
//! not implicit relationships hidden in WHERE.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Issue};
use sqlparser::ast::{
    BinaryOperator, Expr, JoinConstraint, JoinOperator, Select, Statement, TableFactor,
};

use super::semantic_helpers::{table_factor_reference_name, visit_selects_in_statement};

pub struct ConventionJoinCondition;

impl LintRule for ConventionJoinCondition {
    fn code(&self) -> &'static str {
        issue_codes::LINT_CV_012
    }

    fn name(&self) -> &'static str {
        "Join condition convention"
    }

    fn description(&self) -> &'static str {
        "Use `JOIN ... ON ...` instead of `WHERE ...` for join conditions."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut found_violation = false;

        visit_selects_in_statement(statement, &mut |select| {
            if found_violation {
                return;
            }

            if select_has_implicit_where_join(select) {
                found_violation = true;
            }
        });

        if found_violation {
            vec![Issue::warning(
                issue_codes::LINT_CV_012,
                "JOIN clause appears to lack a meaningful join condition.",
            )
            .with_statement(ctx.statement_index)]
        } else {
            Vec::new()
        }
    }
}

fn select_has_implicit_where_join(select: &Select) -> bool {
    for table in &select.from {
        let mut seen_sources = Vec::new();
        let mut bare_join_match_flags = Vec::new();
        collect_table_factor_sources(&table.relation, &mut seen_sources);

        for join in &table.joins {
            let join_sources = collect_table_factor_all_sources(&join.relation);
            let Some(constraint) = join_constraint(&join.join_operator) else {
                seen_sources.extend(join_sources);
                continue;
            };

            let has_explicit_join_clause = matches!(
                constraint,
                JoinConstraint::On(_) | JoinConstraint::Using(_) | JoinConstraint::Natural
            );
            if has_explicit_join_clause {
                seen_sources.extend(join_sources);
                continue;
            }

            let matched_where_predicate = select.selection.as_ref().is_some_and(|where_expr| {
                // For a nested join, any inner source can be the "current" source.
                join_sources.iter().any(|src| {
                    where_contains_join_predicate(where_expr, Some(src), &seen_sources)
                }) || (join_sources.is_empty()
                    && where_contains_join_predicate(where_expr, None, &seen_sources))
            });
            bare_join_match_flags.push(matched_where_predicate);

            seen_sources.extend(join_sources);
        }

        // SQLFluff CV12 parity: only flag when all plain/naked joins in a
        // chain appear to be expressed via WHERE predicates.
        if !bare_join_match_flags.is_empty() && bare_join_match_flags.iter().all(|flag| *flag) {
            return true;
        }
    }

    false
}

/// Adds the reference name for a table factor to the list.
fn collect_table_factor_sources(table_factor: &TableFactor, sources: &mut Vec<String>) {
    if let Some(name) = table_factor_reference_name(table_factor) {
        sources.push(name);
    }
}

/// Collects all table source names from a table factor, including nested join
/// members. For a simple table reference this returns a single name. For a
/// `NestedJoin` it returns all inner table names.
fn collect_table_factor_all_sources(table_factor: &TableFactor) -> Vec<String> {
    let mut sources = Vec::new();
    match table_factor {
        TableFactor::NestedJoin {
            table_with_joins,
            alias,
            ..
        } => {
            if let Some(alias) = alias {
                sources.push(alias.name.value.to_ascii_uppercase());
            } else {
                collect_table_factor_sources(&table_with_joins.relation, &mut sources);
                for join in &table_with_joins.joins {
                    collect_table_factor_sources(&join.relation, &mut sources);
                }
            }
        }
        _ => {
            collect_table_factor_sources(table_factor, &mut sources);
        }
    }
    sources
}

fn join_constraint(join_operator: &JoinOperator) -> Option<&JoinConstraint> {
    match join_operator {
        JoinOperator::Join(constraint)
        | JoinOperator::Inner(constraint)
        | JoinOperator::Left(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::Right(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::FullOuter(constraint)
        | JoinOperator::CrossJoin(constraint)
        | JoinOperator::Semi(constraint)
        | JoinOperator::LeftSemi(constraint)
        | JoinOperator::RightSemi(constraint)
        | JoinOperator::Anti(constraint)
        | JoinOperator::LeftAnti(constraint)
        | JoinOperator::RightAnti(constraint)
        | JoinOperator::StraightJoin(constraint) => Some(constraint),
        JoinOperator::AsOf { constraint, .. } => Some(constraint),
        JoinOperator::CrossApply | JoinOperator::OuterApply => None,
    }
}

fn where_contains_join_predicate(
    expr: &Expr,
    current_source: Option<&String>,
    seen_sources: &[String],
) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            let direct_match = matches!(
                op,
                BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::Gt
                    | BinaryOperator::LtEq
                    | BinaryOperator::GtEq
            ) && is_column_reference(left)
                && is_column_reference(right)
                && references_joined_sources(left, right, current_source, seen_sources);

            direct_match
                || where_contains_join_predicate(left, current_source, seen_sources)
                || where_contains_join_predicate(right, current_source, seen_sources)
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::Cast { expr: inner, .. } => {
            where_contains_join_predicate(inner, current_source, seen_sources)
        }
        Expr::InList { expr, list, .. } => {
            where_contains_join_predicate(expr, current_source, seen_sources)
                || list
                    .iter()
                    .any(|item| where_contains_join_predicate(item, current_source, seen_sources))
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            where_contains_join_predicate(expr, current_source, seen_sources)
                || where_contains_join_predicate(low, current_source, seen_sources)
                || where_contains_join_predicate(high, current_source, seen_sources)
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            operand.as_ref().is_some_and(|expr| {
                where_contains_join_predicate(expr, current_source, seen_sources)
            }) || conditions.iter().any(|when| {
                where_contains_join_predicate(&when.condition, current_source, seen_sources)
                    || where_contains_join_predicate(&when.result, current_source, seen_sources)
            }) || else_result.as_ref().is_some_and(|expr| {
                where_contains_join_predicate(expr, current_source, seen_sources)
            })
        }
        _ => false,
    }
}

fn is_column_reference(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

fn references_joined_sources(
    left: &Expr,
    right: &Expr,
    current_source: Option<&String>,
    seen_sources: &[String],
) -> bool {
    let left_prefix = qualifier_prefix(left);
    let right_prefix = qualifier_prefix(right);

    match (left_prefix, right_prefix, current_source) {
        (Some(left), Some(right), Some(current)) => {
            (left == *current && seen_sources.contains(&right))
                || (right == *current && seen_sources.contains(&left))
        }
        // Unqualified `a = b` in a plain join WHERE is still ambiguous and should fail.
        (None, None, _) => true,
        _ => false,
    }
}

fn qualifier_prefix(expr: &Expr) -> Option<String> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() > 1 => {
            // For `table.col` (2 parts), the qualifier is the first part.
            // For `schema.table.col` (3+ parts), the qualifier is the
            // penultimate part (the table name) since that is what
            // `table_factor_reference_name` extracts as the source name.
            let qualifier_index = parts.len() - 2;
            Some(parts[qualifier_index].value.to_ascii_uppercase())
        }
        Expr::Nested(inner)
        | Expr::UnaryOp { expr: inner, .. }
        | Expr::Cast { expr: inner, .. } => qualifier_prefix(inner),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = ConventionJoinCondition;
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

    // --- Edge cases adopted from sqlfluff CV12 ---

    #[test]
    fn allows_plain_join_without_where_clause() {
        let issues = run("SELECT foo.a, bar.b FROM foo JOIN bar");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_plain_join_with_implicit_where_predicate() {
        let issues = run("SELECT foo.a, bar.b FROM foo JOIN bar WHERE foo.x = bar.y");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_012);
    }

    #[test]
    fn flags_plain_join_with_unqualified_where_predicate() {
        let issues = run("SELECT foo.a, bar.b FROM foo JOIN bar WHERE a = b");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn allows_join_with_explicit_on_clause() {
        let issues = run("SELECT foo.a, bar.b FROM foo LEFT JOIN bar ON foo.x = bar.x");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_cross_join() {
        let issues = run("SELECT foo.a, bar.b FROM foo CROSS JOIN bar WHERE bar.x > 3");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_inner_join_without_on_with_where_predicate() {
        let issues = run("SELECT foo.a, bar.b FROM foo INNER JOIN bar WHERE foo.x = bar.y");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_012);
    }

    #[test]
    fn does_not_flag_multi_join_chain_when_not_all_plain_joins_are_where_joined() {
        let sql = "select a.id from a join b join c where a.a = b.a and b.b > 1";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn flags_multi_join_chain_when_all_plain_joins_are_where_joined() {
        let sql = "select a.id from a join b join c where a.a = b.a and b.b = c.b";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_012);
    }

    #[test]
    fn flags_schema_qualified_where_join() {
        // SQLFluff: test_fail_missing_clause_and_stmt_qualified
        let sql = "SELECT foo.a, bar.b FROM schema.foo JOIN schema.bar WHERE schema.foo.x = schema.bar.y AND schema.foo.x = 3";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_012);
    }

    #[test]
    fn flags_bracketed_join_with_where_predicate() {
        // SQLFluff: test_fail_join_with_bracketed_join
        let sql = "SELECT * FROM bar JOIN (foo1 JOIN foo2 ON (foo1.id = foo2.id)) WHERE bar.id = foo1.id";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_012);
    }
}
