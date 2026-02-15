//! LINT_CV_010: Quoted literals style.
//!
//! SQLFluff CV10 parity (current scope): detect double-quoted literal-like
//! segments.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::linter::visit::visit_expressions;
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::{Statement, Value};

use super::references_quoted_helpers::double_quoted_identifiers_in_statement;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreferredQuotedLiteralStyle {
    Consistent,
    SingleQuotes,
    DoubleQuotes,
}

impl PreferredQuotedLiteralStyle {
    fn from_config(config: &LintConfig) -> Self {
        match config
            .rule_option_str(issue_codes::LINT_CV_010, "preferred_quoted_literal_style")
            .unwrap_or("consistent")
            .to_ascii_lowercase()
            .as_str()
        {
            "single_quotes" | "single" => Self::SingleQuotes,
            "double_quotes" | "double" => Self::DoubleQuotes,
            _ => Self::Consistent,
        }
    }
}

pub struct ConventionQuotedLiterals {
    preferred_style: PreferredQuotedLiteralStyle,
}

impl ConventionQuotedLiterals {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            preferred_style: PreferredQuotedLiteralStyle::from_config(config),
        }
    }
}

impl Default for ConventionQuotedLiterals {
    fn default() -> Self {
        Self {
            preferred_style: PreferredQuotedLiteralStyle::Consistent,
        }
    }
}

impl LintRule for ConventionQuotedLiterals {
    fn code(&self) -> &'static str {
        issue_codes::LINT_CV_010
    }

    fn name(&self) -> &'static str {
        "Quoted literals style"
    }

    fn description(&self) -> &'static str {
        "Consistent usage of preferred quotes for quoted literals."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let has_double_quoted = !double_quoted_identifiers_in_statement(statement).is_empty();
        let has_single_quoted = statement_contains_single_quoted_literal(statement);

        let violation = match self.preferred_style {
            PreferredQuotedLiteralStyle::Consistent => has_double_quoted && has_single_quoted,
            PreferredQuotedLiteralStyle::SingleQuotes => has_double_quoted,
            PreferredQuotedLiteralStyle::DoubleQuotes => has_single_quoted,
        };

        if violation {
            let message = match self.preferred_style {
                PreferredQuotedLiteralStyle::Consistent => {
                    "Quoted literal style appears inconsistent."
                }
                PreferredQuotedLiteralStyle::SingleQuotes => {
                    "Use single quotes for quoted literals."
                }
                PreferredQuotedLiteralStyle::DoubleQuotes => {
                    "Use double quotes for quoted literals."
                }
            };
            let mut issue =
                Issue::info(issue_codes::LINT_CV_010, message).with_statement(ctx.statement_index);

            let autofix_edits = cv010_autofix_edits(ctx.statement_sql(), self.preferred_style)
                .into_iter()
                .map(|edit| {
                    IssuePatchEdit::new(
                        ctx.span_from_statement_offset(edit.start, edit.end),
                        edit.replacement,
                    )
                })
                .collect::<Vec<_>>();
            if !autofix_edits.is_empty() {
                issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, autofix_edits);
            }

            vec![issue]
        } else {
            Vec::new()
        }
    }
}

struct Cv010AutofixEdit {
    start: usize,
    end: usize,
    replacement: String,
}

fn cv010_autofix_edits(
    sql: &str,
    preferred_style: PreferredQuotedLiteralStyle,
) -> Vec<Cv010AutofixEdit> {
    match preferred_style {
        // In most supported dialects, rewriting `'value'` -> `"value"` changes
        // semantics (string literal vs quoted identifier), so keep this
        // report-only in current migration scope.
        PreferredQuotedLiteralStyle::DoubleQuotes => Vec::new(),
        PreferredQuotedLiteralStyle::Consistent | PreferredQuotedLiteralStyle::SingleQuotes => {
            unnecessary_quoted_identifier_edits(sql)
        }
    }
}

fn unnecessary_quoted_identifier_edits(sql: &str) -> Vec<Cv010AutofixEdit> {
    let bytes = sql.as_bytes();
    let mut edits = Vec::new();
    let mut index = 0usize;
    let mut in_single = false;

    while index < bytes.len() {
        if bytes[index] == b'\'' {
            if in_single && index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                index += 2;
                continue;
            }
            in_single = !in_single;
            index += 1;
            continue;
        }

        if in_single || bytes[index] != b'"' {
            index += 1;
            continue;
        }

        let start = index;
        index += 1;
        let ident_start = index;
        let mut escaped_quote = false;
        while index < bytes.len() {
            if bytes[index] == b'"' {
                if index + 1 < bytes.len() && bytes[index + 1] == b'"' {
                    escaped_quote = true;
                    index += 2;
                    continue;
                }
                break;
            }
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let ident_end = index;
        let end = index + 1;
        let Some(ident) = sql.get(ident_start..ident_end) else {
            index += 1;
            continue;
        };

        if !escaped_quote && is_simple_identifier(ident) && can_unquote_identifier_safely(ident) {
            edits.push(Cv010AutofixEdit {
                start,
                end,
                replacement: ident.to_string(),
            });
        }

        index = end;
    }

    edits
}

fn is_simple_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !is_ascii_ident_start(bytes[0]) {
        return false;
    }
    bytes[1..].iter().copied().all(is_ascii_ident_continue)
}

fn is_ascii_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ascii_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn can_unquote_identifier_safely(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    let starts_ok = first.is_ascii_lowercase() || first == '_';
    let rest_ok = chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');

    starts_ok && rest_ok && !is_sql_keyword(identifier)
}

fn is_sql_keyword(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        "ALL"
            | "ALTER"
            | "AND"
            | "ANY"
            | "AS"
            | "ASC"
            | "BEGIN"
            | "BETWEEN"
            | "BOOLEAN"
            | "BY"
            | "CASE"
            | "CAST"
            | "CHECK"
            | "COLUMN"
            | "CONSTRAINT"
            | "CREATE"
            | "CROSS"
            | "DEFAULT"
            | "DELETE"
            | "DESC"
            | "DISTINCT"
            | "DROP"
            | "ELSE"
            | "END"
            | "EXCEPT"
            | "EXISTS"
            | "FALSE"
            | "FETCH"
            | "FOR"
            | "FOREIGN"
            | "FROM"
            | "FULL"
            | "GROUP"
            | "HAVING"
            | "IF"
            | "IN"
            | "INDEX"
            | "INNER"
            | "INSERT"
            | "INT"
            | "INTEGER"
            | "INTERSECT"
            | "INTO"
            | "IS"
            | "JOIN"
            | "KEY"
            | "LEFT"
            | "LIKE"
            | "LIMIT"
            | "NOT"
            | "NULL"
            | "OFFSET"
            | "ON"
            | "OR"
            | "ORDER"
            | "OUTER"
            | "OVER"
            | "PARTITION"
            | "PRIMARY"
            | "REFERENCES"
            | "RIGHT"
            | "SELECT"
            | "SET"
            | "TABLE"
            | "TEXT"
            | "THEN"
            | "TO"
            | "TRUE"
            | "UNION"
            | "UNIQUE"
            | "UPDATE"
            | "USING"
            | "VALUES"
            | "VIEW"
            | "WHEN"
            | "WHERE"
            | "WITH"
    )
}

fn statement_contains_single_quoted_literal(statement: &Statement) -> bool {
    let mut found = false;
    visit_expressions(statement, &mut |expr| {
        if found {
            return;
        }
        if let sqlparser::ast::Expr::Value(value) = expr {
            found = matches!(
                value.value,
                Value::SingleQuotedString(_)
                    | Value::DollarQuotedString(_)
                    | Value::NationalStringLiteral(_)
                    | Value::EscapedStringLiteral(_)
            );
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = ConventionQuotedLiterals::default();
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

    #[test]
    fn flags_mixed_quote_styles_in_consistent_mode() {
        let sql = "SELECT 'abc' AS a, \"def\" AS b FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_010);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 'abc' AS a, def AS b FROM t");
    }

    #[test]
    fn does_not_flag_single_quoted_literal() {
        assert!(run("SELECT 'abc' FROM t").is_empty());
    }

    #[test]
    fn does_not_flag_only_double_quoted_literal_like_token() {
        assert!(run("SELECT \"abc\" FROM t").is_empty());
    }

    #[test]
    fn does_not_flag_double_quotes_inside_single_quoted_literal() {
        assert!(run("SELECT '\"abc\"' FROM t").is_empty());
    }

    #[test]
    fn single_quotes_preference_flags_double_quoted_identifier_usage() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.quoted_literals".to_string(),
                serde_json::json!({"preferred_quoted_literal_style": "single_quotes"}),
            )]),
        };
        let rule = ConventionQuotedLiterals::from_config(&config);
        let sql = "SELECT \"abc\" FROM t";
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
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT abc FROM t");
    }

    #[test]
    fn double_quotes_preference_flags_single_quoted_literal_usage() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CV_010".to_string(),
                serde_json::json!({"preferred_quoted_literal_style": "double_quotes"}),
            )]),
        };
        let rule = ConventionQuotedLiterals::from_config(&config);
        let sql = "SELECT 'abc' FROM t";
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
        assert!(
            issues[0].autofix.is_none(),
            "double quote preference remains report-only in conservative CV010 migration scope"
        );
    }
}
