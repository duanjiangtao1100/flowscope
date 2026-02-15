//! LINT_RF_003: References consistency.
//!
//! In single-source queries, avoid mixing qualified and unqualified references.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::{Select, SelectItem, Statement};

use super::semantic_helpers::{
    count_reference_qualification_in_expr_excluding_aliases, select_projection_alias_set,
    select_source_count, visit_select_expressions, visit_selects_in_statement,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SingleTableReferencesMode {
    Consistent,
    Qualified,
    Unqualified,
}

impl SingleTableReferencesMode {
    fn from_config(config: &LintConfig) -> Self {
        match config
            .rule_option_str(issue_codes::LINT_RF_003, "single_table_references")
            .unwrap_or("consistent")
            .to_ascii_lowercase()
            .as_str()
        {
            "qualified" => Self::Qualified,
            "unqualified" => Self::Unqualified,
            _ => Self::Consistent,
        }
    }

    fn violation(self, qualified: usize, unqualified: usize) -> bool {
        match self {
            Self::Consistent => qualified > 0 && unqualified > 0,
            Self::Qualified => unqualified > 0,
            Self::Unqualified => qualified > 0,
        }
    }
}

pub struct ReferencesConsistent {
    single_table_references: SingleTableReferencesMode,
    force_enable: bool,
}

impl ReferencesConsistent {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            single_table_references: SingleTableReferencesMode::from_config(config),
            force_enable: config
                .rule_option_bool(issue_codes::LINT_RF_003, "force_enable")
                .unwrap_or(true),
        }
    }
}

impl Default for ReferencesConsistent {
    fn default() -> Self {
        Self {
            single_table_references: SingleTableReferencesMode::Consistent,
            force_enable: true,
        }
    }
}

impl LintRule for ReferencesConsistent {
    fn code(&self) -> &'static str {
        issue_codes::LINT_RF_003
    }

    fn name(&self) -> &'static str {
        "References consistent"
    }

    fn description(&self) -> &'static str {
        "Column references should be qualified consistently in single table statements."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        if !self.force_enable {
            return Vec::new();
        }

        let mut mixed_count = 0usize;

        visit_selects_in_statement(statement, &mut |select| {
            if select_source_count(select) != 1 {
                return;
            }

            let aliases = select_projection_alias_set(select);
            let mut qualified = 0usize;
            let mut unqualified = 0usize;

            visit_select_expressions(select, &mut |expr| {
                let (q, u) =
                    count_reference_qualification_in_expr_excluding_aliases(expr, &aliases);
                qualified += q;
                unqualified += u;
            });
            let (projection_qualified, projection_unqualified) =
                projection_wildcard_qualification_counts(select);
            qualified += projection_qualified;
            unqualified += projection_unqualified;

            if self
                .single_table_references
                .violation(qualified, unqualified)
            {
                mixed_count += 1;
            }
        });

        if mixed_count == 0 {
            return Vec::new();
        }

        let autofix_edits = mixed_reference_autofix_edits(ctx.statement_sql())
            .into_iter()
            .map(|edit| {
                IssuePatchEdit::new(
                    ctx.span_from_statement_offset(edit.start, edit.end),
                    edit.replacement,
                )
            })
            .collect::<Vec<_>>();

        (0..mixed_count)
            .map(|index| {
                let mut issue = Issue::info(
                    issue_codes::LINT_RF_003,
                    "Avoid mixing qualified and unqualified references.",
                )
                .with_statement(ctx.statement_index);
                if index == 0 && !autofix_edits.is_empty() {
                    issue = issue
                        .with_autofix_edits(IssueAutofixApplicability::Safe, autofix_edits.clone());
                }
                issue
            })
            .collect()
    }
}

struct Rf003AutofixEdit {
    start: usize,
    end: usize,
    replacement: String,
}

fn mixed_reference_autofix_edits(sql: &str) -> Vec<Rf003AutofixEdit> {
    let bytes = sql.as_bytes();
    let Some(select_start) = find_ascii_keyword(bytes, b"SELECT", 0) else {
        return Vec::new();
    };
    let select_end = select_start + b"SELECT".len();
    let Some(from_start) = find_ascii_keyword(bytes, b"FROM", select_end) else {
        return Vec::new();
    };

    let Some((table_name, alias)) = extract_from_table_and_alias(sql) else {
        return Vec::new();
    };
    let prefix = if alias.is_empty() {
        table_name.rsplit('.').next().unwrap_or(&table_name)
    } else {
        alias.as_str()
    };
    if prefix.is_empty() {
        return Vec::new();
    }

    let select_clause = &sql[select_end..from_start];
    let projection_items = split_projection_items(select_clause);
    if projection_items.is_empty() {
        return Vec::new();
    }

    let has_qualified = projection_items
        .iter()
        .any(|(value, _, _)| is_simple_qualified_identifier(value));
    let has_unqualified = projection_items
        .iter()
        .any(|(value, _, _)| is_simple_identifier(value));
    if !(has_qualified && has_unqualified) {
        return Vec::new();
    }

    projection_items
        .into_iter()
        .filter_map(|(value, start, end)| {
            if !is_simple_identifier(&value) {
                return None;
            }
            Some(Rf003AutofixEdit {
                start: select_end + start,
                end: select_end + end,
                replacement: format!("{prefix}.{value}"),
            })
        })
        .collect()
}

fn split_projection_items(select_clause: &str) -> Vec<(String, usize, usize)> {
    let bytes = select_clause.as_bytes();
    let mut out = Vec::new();
    let mut segment_start = 0usize;
    let mut index = 0usize;

    while index <= bytes.len() {
        if index == bytes.len() || bytes[index] == b',' {
            let segment = &select_clause[segment_start..index];
            let leading_trim = segment
                .char_indices()
                .find(|(_, ch)| !ch.is_ascii_whitespace())
                .map(|(idx, _)| idx)
                .unwrap_or(segment.len());
            let trailing_trim = segment
                .char_indices()
                .rfind(|(_, ch)| !ch.is_ascii_whitespace())
                .map(|(idx, ch)| idx + ch.len_utf8())
                .unwrap_or(leading_trim);

            if leading_trim < trailing_trim {
                let value = segment[leading_trim..trailing_trim].to_string();
                out.push((
                    value,
                    segment_start + leading_trim,
                    segment_start + trailing_trim,
                ));
            }
            segment_start = index + 1;
        }
        index += 1;
    }

    out
}

fn extract_from_table_and_alias(sql: &str) -> Option<(String, String)> {
    let bytes = sql.as_bytes();
    let from_start = find_ascii_keyword(bytes, b"FROM", 0)?;
    let mut index = skip_ascii_whitespace(bytes, from_start + b"FROM".len());
    let table_start = index;
    index = consume_ascii_identifier(bytes, index)?;
    while index < bytes.len() && bytes[index] == b'.' {
        let next = consume_ascii_identifier(bytes, index + 1)?;
        index = next;
    }
    let table_name = sql[table_start..index].to_string();

    let mut alias = String::new();
    let after_table = skip_ascii_whitespace(bytes, index);
    if after_table > index {
        if let Some(as_end) = match_ascii_keyword_at(bytes, after_table, b"AS") {
            let alias_start = skip_ascii_whitespace(bytes, as_end);
            if alias_start > as_end {
                if let Some(alias_end) = consume_ascii_identifier(bytes, alias_start) {
                    alias = sql[alias_start..alias_end].to_string();
                }
            }
        } else if let Some(alias_end) = consume_ascii_identifier(bytes, after_table) {
            alias = sql[after_table..alias_end].to_string();
        }
    }

    Some((table_name, alias))
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

fn find_ascii_keyword(bytes: &[u8], keyword_upper: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + keyword_upper.len() <= bytes.len() {
        if match_ascii_keyword_at(bytes, index, keyword_upper).is_some() {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn is_simple_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !is_ascii_ident_start(bytes[0]) {
        return false;
    }
    bytes[1..].iter().copied().all(is_ascii_ident_continue)
}

fn is_simple_qualified_identifier(value: &str) -> bool {
    let mut parts = value.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(left), Some(right), None) => {
            is_simple_identifier(left) && is_simple_identifier(right)
        }
        _ => false,
    }
}

fn projection_wildcard_qualification_counts(select: &Select) -> (usize, usize) {
    let mut qualified = 0usize;

    for item in &select.projection {
        match item {
            // SQLFluff RF03 parity: treat qualified wildcards as qualified references.
            SelectItem::QualifiedWildcard(_, _) => qualified += 1,
            // Keep unqualified wildcard neutral to avoid forcing `SELECT *` style choices.
            SelectItem::Wildcard(_) => {}
            _ => {}
        }
    }

    (qualified, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = ReferencesConsistent::default();
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

    // --- Edge cases adopted from sqlfluff RF03 ---

    #[test]
    fn flags_mixed_qualification_single_table() {
        let sql = "SELECT my_tbl.bar, baz FROM my_tbl";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_RF_003);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT my_tbl.bar, my_tbl.baz FROM my_tbl");
    }

    #[test]
    fn allows_consistently_unqualified_references() {
        let issues = run("SELECT bar FROM my_tbl");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_consistently_qualified_references() {
        let issues = run("SELECT my_tbl.bar FROM my_tbl");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_mixed_qualification_in_subquery() {
        let issues = run("SELECT * FROM (SELECT my_tbl.bar, baz FROM my_tbl)");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn allows_consistent_references_in_subquery() {
        let issues = run("SELECT * FROM (SELECT my_tbl.bar FROM my_tbl)");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_mixed_qualification_with_qualified_wildcard() {
        let issues = run("SELECT my_tbl.*, bar FROM my_tbl");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn allows_consistent_qualified_wildcard_and_columns() {
        let issues = run("SELECT my_tbl.*, my_tbl.bar FROM my_tbl");
        assert!(issues.is_empty());
    }

    #[test]
    fn qualified_mode_flags_unqualified_references() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "references.consistent".to_string(),
                serde_json::json!({"single_table_references": "qualified"}),
            )]),
        };
        let rule = ReferencesConsistent::from_config(&config);
        let sql = "SELECT bar FROM my_tbl";
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
    }

    #[test]
    fn force_enable_false_disables_rule() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_RF_003".to_string(),
                serde_json::json!({"force_enable": false}),
            )]),
        };
        let rule = ReferencesConsistent::from_config(&config);
        let sql = "SELECT my_tbl.bar, baz FROM my_tbl";
        let statements = parse_sql(sql).expect("parse");
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
}
