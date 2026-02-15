//! LINT_ST_005: Structure subquery.
//!
//! SQLFluff ST05 parity: avoid subqueries in FROM/JOIN clauses; prefer CTEs.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::{Query, Select, SetExpr, Statement, TableFactor};
use std::collections::HashSet;

use super::semantic_helpers::{
    collect_qualifier_prefixes_in_expr, visit_select_expressions, visit_selects_in_statement,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForbidSubqueryIn {
    Both,
    Join,
    From,
}

impl ForbidSubqueryIn {
    fn from_config(config: &LintConfig) -> Self {
        match config
            .rule_option_str(issue_codes::LINT_ST_005, "forbid_subquery_in")
            .unwrap_or("join")
            .to_ascii_lowercase()
            .as_str()
        {
            "join" => Self::Join,
            "from" => Self::From,
            _ => Self::Both,
        }
    }

    fn forbid_from(self) -> bool {
        matches!(self, Self::Both | Self::From)
    }

    fn forbid_join(self) -> bool {
        matches!(self, Self::Both | Self::Join)
    }
}

pub struct StructureSubquery {
    forbid_subquery_in: ForbidSubqueryIn,
}

impl StructureSubquery {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            forbid_subquery_in: ForbidSubqueryIn::from_config(config),
        }
    }
}

impl Default for StructureSubquery {
    fn default() -> Self {
        Self {
            forbid_subquery_in: ForbidSubqueryIn::Join,
        }
    }
}

impl LintRule for StructureSubquery {
    fn code(&self) -> &'static str {
        issue_codes::LINT_ST_005
    }

    fn name(&self) -> &'static str {
        "Structure subquery"
    }

    fn description(&self) -> &'static str {
        "Join/From clauses should not contain subqueries. Use CTEs instead."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut violations = 0usize;

        visit_selects_in_statement(statement, &mut |select| {
            let outer_source_names = source_names_in_select(select);
            for table in &select.from {
                if self.forbid_subquery_in.forbid_from()
                    && table_factor_contains_derived(&table.relation, &outer_source_names)
                {
                    violations += 1;
                }
                if self.forbid_subquery_in.forbid_join() {
                    for join in &table.joins {
                        if table_factor_contains_derived(&join.relation, &outer_source_names) {
                            violations += 1;
                        }
                    }
                }
            }
        });

        if violations == 0 {
            return Vec::new();
        }

        let autofix_edits =
            st005_subquery_to_cte_rewrite(ctx.statement_sql(), self.forbid_subquery_in)
                .filter(|rewritten| rewritten != ctx.statement_sql())
                .map(|rewritten| {
                    vec![IssuePatchEdit::new(
                        ctx.span_from_statement_offset(0, ctx.statement_sql().len()),
                        rewritten,
                    )]
                })
                .unwrap_or_default();

        (0..violations)
            .map(|index| {
                let mut issue = Issue::info(
                    issue_codes::LINT_ST_005,
                    "Join/From clauses should not contain subqueries. Use CTEs instead.",
                )
                .with_statement(ctx.statement_index);
                if index == 0 && !autofix_edits.is_empty() {
                    issue = issue.with_autofix_edits(
                        IssueAutofixApplicability::Unsafe,
                        autofix_edits.clone(),
                    );
                }
                issue
            })
            .collect()
    }
}

fn st005_subquery_to_cte_rewrite(
    sql: &str,
    forbid_subquery_in: ForbidSubqueryIn,
) -> Option<String> {
    if !forbid_subquery_in.forbid_from() {
        return None;
    }

    let bytes = sql.as_bytes();
    let mut index = skip_ascii_whitespace(bytes, 0);
    let select_end = match_ascii_keyword_at(bytes, index, b"SELECT")?;
    index = skip_ascii_whitespace(bytes, select_end);
    if index == select_end || index >= bytes.len() || bytes[index] != b'*' {
        return None;
    }
    index += 1;

    let from_start = skip_ascii_whitespace(bytes, index);
    if from_start == index {
        return None;
    }
    let from_end = match_ascii_keyword_at(bytes, from_start, b"FROM")?;
    let open_paren_index = skip_ascii_whitespace(bytes, from_end);
    if open_paren_index == from_end
        || open_paren_index >= bytes.len()
        || bytes[open_paren_index] != b'('
    {
        return None;
    }

    let close_paren_index = find_matching_parenthesis_outside_quotes(sql, open_paren_index)?;
    let subquery = sql[open_paren_index + 1..close_paren_index].trim();
    if !subquery.to_ascii_lowercase().starts_with("select") {
        return None;
    }

    let suffix = &sql[close_paren_index + 1..];
    let alias = parse_subquery_alias_suffix(suffix)?;

    let mut rewritten = format!("WITH {alias} AS ({subquery}) SELECT * FROM {alias}");
    if suffix.trim_end().ends_with(';') {
        rewritten.push(';');
    }
    Some(rewritten)
}

fn parse_subquery_alias_suffix(suffix: &str) -> Option<String> {
    let bytes = suffix.as_bytes();
    let mut index = skip_ascii_whitespace(bytes, 0);
    if let Some(as_end) = match_ascii_keyword_at(bytes, index, b"AS") {
        let after_as = skip_ascii_whitespace(bytes, as_end);
        if after_as == as_end {
            return None;
        }
        index = after_as;
    }

    let alias_start = index;
    let alias_end = consume_ascii_identifier(bytes, alias_start)?;
    index = skip_ascii_whitespace(bytes, alias_end);
    if index < bytes.len() && bytes[index] == b';' {
        index += 1;
        index = skip_ascii_whitespace(bytes, index);
    }
    if index != bytes.len() {
        return None;
    }

    Some(suffix[alias_start..alias_end].to_string())
}

fn find_matching_parenthesis_outside_quotes(sql: &str, open_paren_index: usize) -> Option<usize> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Outside,
        SingleQuote,
        DoubleQuote,
        BacktickQuote,
        BracketQuote,
    }

    let bytes = sql.as_bytes();
    if open_paren_index >= bytes.len() || bytes[open_paren_index] != b'(' {
        return None;
    }

    let mut depth = 0usize;
    let mut mode = Mode::Outside;
    let mut index = open_paren_index;

    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();

        match mode {
            Mode::Outside => {
                if byte == b'\'' {
                    mode = Mode::SingleQuote;
                    index += 1;
                    continue;
                }
                if byte == b'"' {
                    mode = Mode::DoubleQuote;
                    index += 1;
                    continue;
                }
                if byte == b'`' {
                    mode = Mode::BacktickQuote;
                    index += 1;
                    continue;
                }
                if byte == b'[' {
                    mode = Mode::BracketQuote;
                    index += 1;
                    continue;
                }
                if byte == b'(' {
                    depth += 1;
                    index += 1;
                    continue;
                }
                if byte == b')' {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(index);
                    }
                }
                index += 1;
            }
            Mode::SingleQuote => {
                if byte == b'\'' {
                    if next == Some(b'\'') {
                        index += 2;
                    } else {
                        mode = Mode::Outside;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            Mode::DoubleQuote => {
                if byte == b'"' {
                    if next == Some(b'"') {
                        index += 2;
                    } else {
                        mode = Mode::Outside;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            Mode::BacktickQuote => {
                if byte == b'`' {
                    if next == Some(b'`') {
                        index += 2;
                    } else {
                        mode = Mode::Outside;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            Mode::BracketQuote => {
                if byte == b']' {
                    if next == Some(b']') {
                        index += 2;
                    } else {
                        mode = Mode::Outside;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
        }
    }

    None
}

fn is_ascii_whitespace_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn is_ascii_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ascii_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && is_ascii_whitespace_byte(bytes[index]) {
        index += 1;
    }
    index
}

fn consume_ascii_identifier(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() || !is_ascii_ident_start(bytes[start]) {
        return None;
    }
    let mut index = start + 1;
    while index < bytes.len() && is_ascii_ident_continue(bytes[index]) {
        index += 1;
    }
    Some(index)
}

fn is_word_boundary_for_keyword(bytes: &[u8], index: usize) -> bool {
    index == 0 || index >= bytes.len() || !is_ascii_ident_continue(bytes[index])
}

fn match_ascii_keyword_at(bytes: &[u8], start: usize, keyword_upper: &[u8]) -> Option<usize> {
    let end = start.checked_add(keyword_upper.len())?;
    if end > bytes.len() {
        return None;
    }
    if !is_word_boundary_for_keyword(bytes, start.saturating_sub(1))
        || !is_word_boundary_for_keyword(bytes, end)
    {
        return None;
    }
    let matches = bytes[start..end]
        .iter()
        .zip(keyword_upper.iter())
        .all(|(actual, expected)| actual.to_ascii_uppercase() == *expected);
    if matches {
        Some(end)
    } else {
        None
    }
}

fn table_factor_contains_derived(
    table_factor: &TableFactor,
    outer_source_names: &HashSet<String>,
) -> bool {
    match table_factor {
        TableFactor::Derived { subquery, .. } => {
            !query_references_outer_sources(subquery, outer_source_names)
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            table_factor_contains_derived(&table_with_joins.relation, outer_source_names)
                || table_with_joins
                    .joins
                    .iter()
                    .any(|join| table_factor_contains_derived(&join.relation, outer_source_names))
        }
        TableFactor::Pivot { table, .. }
        | TableFactor::Unpivot { table, .. }
        | TableFactor::MatchRecognize { table, .. } => {
            table_factor_contains_derived(table, outer_source_names)
        }
        _ => false,
    }
}

fn query_references_outer_sources(query: &Query, outer_source_names: &HashSet<String>) -> bool {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if query_references_outer_sources(&cte.query, outer_source_names) {
                return true;
            }
        }
    }

    set_expr_references_outer_sources(&query.body, outer_source_names)
}

fn set_expr_references_outer_sources(
    set_expr: &SetExpr,
    outer_source_names: &HashSet<String>,
) -> bool {
    match set_expr {
        SetExpr::Select(select) => select_references_outer_sources(select, outer_source_names),
        SetExpr::Query(query) => query_references_outer_sources(query, outer_source_names),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_references_outer_sources(left, outer_source_names)
                || set_expr_references_outer_sources(right, outer_source_names)
        }
        _ => false,
    }
}

fn select_references_outer_sources(select: &Select, outer_source_names: &HashSet<String>) -> bool {
    let mut qualifier_prefixes = HashSet::new();
    visit_select_expressions(select, &mut |expr| {
        collect_qualifier_prefixes_in_expr(expr, &mut qualifier_prefixes);
    });

    let local_source_names = source_names_in_select(select);
    if qualifier_prefixes
        .iter()
        .any(|name| outer_source_names.contains(name) && !local_source_names.contains(name))
    {
        return true;
    }

    for table in &select.from {
        if table_factor_references_outer_sources(&table.relation, outer_source_names) {
            return true;
        }
        for join in &table.joins {
            if table_factor_references_outer_sources(&join.relation, outer_source_names) {
                return true;
            }
        }
    }
    false
}

fn table_factor_references_outer_sources(
    table_factor: &TableFactor,
    outer_source_names: &HashSet<String>,
) -> bool {
    match table_factor {
        TableFactor::Derived { subquery, .. } => {
            query_references_outer_sources(subquery, outer_source_names)
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            table_factor_references_outer_sources(&table_with_joins.relation, outer_source_names)
                || table_with_joins.joins.iter().any(|join| {
                    table_factor_references_outer_sources(&join.relation, outer_source_names)
                })
        }
        TableFactor::Pivot { table, .. }
        | TableFactor::Unpivot { table, .. }
        | TableFactor::MatchRecognize { table, .. } => {
            table_factor_references_outer_sources(table, outer_source_names)
        }
        _ => false,
    }
}

fn source_names_in_select(select: &Select) -> HashSet<String> {
    let mut names = HashSet::new();
    for table in &select.from {
        collect_source_names_from_table_factor(&table.relation, &mut names);
        for join in &table.joins {
            collect_source_names_from_table_factor(&join.relation, &mut names);
        }
    }
    names
}

fn collect_source_names_from_table_factor(table_factor: &TableFactor, names: &mut HashSet<String>) {
    match table_factor {
        TableFactor::Table { name, alias, .. } => {
            if let Some(last) = name.0.last().and_then(|part| part.as_ident()) {
                names.insert(last.value.to_ascii_uppercase());
            }
            if let Some(alias) = alias {
                names.insert(alias.name.value.to_ascii_uppercase());
            }
        }
        TableFactor::Derived {
            alias, subquery, ..
        } => {
            if let Some(alias) = alias {
                names.insert(alias.name.value.to_ascii_uppercase());
            }
            if let Some(with) = &subquery.with {
                for cte in &with.cte_tables {
                    names.insert(cte.alias.name.value.to_ascii_uppercase());
                }
            }
        }
        TableFactor::TableFunction { alias, .. }
        | TableFactor::Function { alias, .. }
        | TableFactor::UNNEST { alias, .. }
        | TableFactor::JsonTable { alias, .. }
        | TableFactor::OpenJsonTable { alias, .. } => {
            if let Some(alias) = alias {
                names.insert(alias.name.value.to_ascii_uppercase());
            }
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            collect_source_names_from_table_factor(&table_with_joins.relation, names);
            for join in &table_with_joins.joins {
                collect_source_names_from_table_factor(&join.relation, names);
            }
        }
        TableFactor::Pivot { table, .. }
        | TableFactor::Unpivot { table, .. }
        | TableFactor::MatchRecognize { table, .. } => {
            collect_source_names_from_table_factor(table, names);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::{config::LintConfig, rule::LintContext, Linter};
    use crate::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse sql");
        let linter = Linter::new(LintConfig::default());
        let stmt = &statements[0];
        let ctx = LintContext {
            sql,
            statement_range: 0..sql.len(),
            statement_index: 0,
        };
        linter.check_statement(stmt, &ctx)
    }

    fn apply_issue_autofix(sql: &str, issue: &Issue) -> Option<String> {
        let autofix = issue.autofix.as_ref()?;
        let mut out = sql.to_string();
        let mut edits = autofix.edits.clone();
        edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
        for edit in edits.into_iter().rev() {
            out.replace_range(edit.span.start..edit.span.end, &edit.replacement);
        }
        Some(out)
    }

    #[test]
    fn default_does_not_flag_subquery_in_from() {
        let issues = run("SELECT * FROM (SELECT * FROM t) sub");
        assert!(!issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn default_flags_subquery_in_join() {
        let issues = run("SELECT * FROM t JOIN (SELECT * FROM u) sub ON t.id = sub.id");
        assert!(issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn default_allows_correlated_subquery_join_without_alias() {
        let issues = run("SELECT pd.* \
             FROM person_dates \
             JOIN (SELECT * FROM events WHERE events.name = person_dates.name)");
        assert!(!issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn default_allows_correlated_subquery_join_with_alias_reference() {
        let issues = run("SELECT pd.* \
             FROM person_dates AS pd \
             JOIN (SELECT * FROM events AS ce WHERE ce.name = pd.name)");
        assert!(!issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn default_allows_correlated_subquery_join_with_outer_table_name_reference() {
        let issues = run("SELECT pd.* \
             FROM person_dates AS pd \
             JOIN (SELECT * FROM events AS ce WHERE ce.name = person_dates.name)");
        assert!(!issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn does_not_flag_cte_usage() {
        let issues = run("WITH sub AS (SELECT * FROM t) SELECT * FROM sub");
        assert!(!issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn does_not_flag_scalar_subquery_in_where() {
        let issues = run("SELECT * FROM t WHERE id IN (SELECT id FROM u)");
        assert!(!issues
            .iter()
            .any(|issue| issue.code == issue_codes::LINT_ST_005));
    }

    #[test]
    fn forbid_subquery_in_join_does_not_flag_from_subquery() {
        let sql = "SELECT * FROM (SELECT * FROM t) sub";
        let statements = parse_sql(sql).expect("parse sql");
        let rule = StructureSubquery::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "structure.subquery".to_string(),
                serde_json::json!({"forbid_subquery_in": "join"}),
            )]),
        });
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn forbid_subquery_in_from_emits_unsafe_cte_autofix_for_simple_case() {
        let sql = "SELECT * FROM (SELECT 1) sub";
        let statements = parse_sql(sql).expect("parse sql");
        let rule = StructureSubquery::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_ST_005".to_string(),
                serde_json::json!({"forbid_subquery_in": "from"}),
            )]),
        });
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Unsafe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "WITH sub AS (SELECT 1) SELECT * FROM sub");
    }

    #[test]
    fn forbid_subquery_in_from_does_not_flag_join_subquery() {
        let sql = "SELECT * FROM t JOIN (SELECT * FROM u) sub ON t.id = sub.id";
        let statements = parse_sql(sql).expect("parse sql");
        let rule = StructureSubquery::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_ST_005".to_string(),
                serde_json::json!({"forbid_subquery_in": "from"}),
            )]),
        });
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn forbid_both_flags_subquery_inside_cte_body() {
        let sql = "WITH b AS (SELECT x, z FROM (SELECT x, z FROM p_cte)) SELECT b.z FROM b";
        let statements = parse_sql(sql).expect("parse sql");
        let rule = StructureSubquery::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "structure.subquery".to_string(),
                serde_json::json!({"forbid_subquery_in": "both"}),
            )]),
        });
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn forbid_both_flags_subqueries_in_set_operation_second_branch() {
        let sql = "SELECT 1 AS value_name UNION SELECT value FROM (SELECT 2 AS value_name) CROSS JOIN (SELECT 1 AS v2)";
        let statements = parse_sql(sql).expect("parse sql");
        let rule = StructureSubquery::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "structure.subquery".to_string(),
                serde_json::json!({"forbid_subquery_in": "both"}),
            )]),
        });
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 2);
    }
}
