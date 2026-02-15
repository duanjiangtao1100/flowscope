//! LINT_CP_005: Type capitalisation.
//!
//! SQLFluff CP05 parity (current scope): detect mixed-case type names.

use std::collections::HashSet;

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use regex::Regex;
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer};

use super::capitalisation_policy_helpers::{
    ignored_words_from_config, ignored_words_regex_from_config, token_is_ignored,
    tokens_violate_policy, CapitalisationPolicy,
};

pub struct CapitalisationTypes {
    policy: CapitalisationPolicy,
    ignore_words: HashSet<String>,
    ignore_words_regex: Option<Regex>,
}

impl CapitalisationTypes {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            policy: CapitalisationPolicy::from_rule_config(
                config,
                issue_codes::LINT_CP_005,
                "extended_capitalisation_policy",
            ),
            ignore_words: ignored_words_from_config(config, issue_codes::LINT_CP_005),
            ignore_words_regex: ignored_words_regex_from_config(config, issue_codes::LINT_CP_005),
        }
    }
}

impl Default for CapitalisationTypes {
    fn default() -> Self {
        Self {
            policy: CapitalisationPolicy::Consistent,
            ignore_words: HashSet::new(),
            ignore_words_regex: None,
        }
    }
}

impl LintRule for CapitalisationTypes {
    fn code(&self) -> &'static str {
        issue_codes::LINT_CP_005
    }

    fn name(&self) -> &'static str {
        "Type capitalisation"
    }

    fn description(&self) -> &'static str {
        "Inconsistent capitalisation of datatypes."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let types =
            type_tokens_for_context(ctx, &self.ignore_words, self.ignore_words_regex.as_ref());
        let type_values = types
            .iter()
            .map(|candidate| candidate.value.clone())
            .collect::<Vec<_>>();
        if !tokens_violate_policy(&type_values, self.policy) {
            return Vec::new();
        }

        let mut issue = Issue::info(
            issue_codes::LINT_CP_005,
            "Type names use inconsistent capitalisation.",
        )
        .with_statement(ctx.statement_index);

        let autofix_edits = type_autofix_edits(ctx, &types, self.policy);
        if !autofix_edits.is_empty() {
            issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, autofix_edits);
        }

        vec![issue]
    }
}

#[derive(Clone)]
struct TypeCandidate {
    value: String,
    start: usize,
    end: usize,
}

fn type_tokens_for_context(
    ctx: &LintContext,
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> Vec<TypeCandidate> {
    let from_document_tokens = ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        let mut statement_tokens = Vec::new();
        for token in tokens {
            let Some((start, end)) = token_with_span_offsets(ctx.sql, token) else {
                continue;
            };
            if start < ctx.statement_range.start || end > ctx.statement_range.end {
                continue;
            }

            if let Token::Word(word) = &token.token {
                // Document token spans are tied to rendered SQL. If the source
                // slice does not match the token text, fall back to
                // statement-local tokenization.
                if !source_word_matches(ctx.sql, start, end, word.value.as_str()) {
                    return None;
                }
            }

            statement_tokens.push(token.clone());
        }

        Some(type_candidates_from_tokens(
            ctx.sql,
            ctx.statement_range.start,
            &statement_tokens,
            ignore_words,
            ignore_words_regex,
        ))
    });

    if let Some(tokens) = from_document_tokens {
        return tokens;
    }

    type_tokens(
        ctx.statement_sql(),
        ignore_words,
        ignore_words_regex,
        ctx.dialect(),
    )
}

fn type_tokens(
    sql: &str,
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
    dialect: Dialect,
) -> Vec<TypeCandidate> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let Ok(tokens) = tokenizer.tokenize_with_location() else {
        return Vec::new();
    };

    type_candidates_from_tokens(sql, 0, &tokens, ignore_words, ignore_words_regex)
}

fn type_candidates_from_tokens(
    sql: &str,
    statement_start: usize,
    tokens: &[TokenWithSpan],
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> Vec<TypeCandidate> {
    let user_defined_types = collect_user_defined_type_names(tokens);

    tokens
        .iter()
        .filter_map(|token| {
            if let Token::Word(word) = &token.token {
                let is_candidate = word.quote_style.is_none()
                    && (is_tracked_type_name(word.value.as_str())
                        || user_defined_types.contains(&word.value.to_ascii_uppercase()))
                    && !token_is_ignored(word.value.as_str(), ignore_words, ignore_words_regex);
                if is_candidate {
                    let (start, end) = token_with_span_offsets(sql, token)?;
                    let local_start = start.checked_sub(statement_start)?;
                    let local_end = end.checked_sub(statement_start)?;
                    return Some(TypeCandidate {
                        value: word.value.clone(),
                        start: local_start,
                        end: local_end,
                    });
                }
            }

            None
        })
        .collect()
}

fn type_autofix_edits(
    ctx: &LintContext,
    types: &[TypeCandidate],
    policy: CapitalisationPolicy,
) -> Vec<IssuePatchEdit> {
    let mut edits = Vec::new();

    for candidate in types {
        let Some(replacement) = type_case_replacement(candidate.value.as_str(), policy) else {
            continue;
        };
        if replacement == candidate.value {
            continue;
        }

        edits.push(IssuePatchEdit::new(
            ctx.span_from_statement_offset(candidate.start, candidate.end),
            replacement,
        ));
    }

    edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
    edits.dedup_by(|left, right| {
        left.span.start == right.span.start
            && left.span.end == right.span.end
            && left.replacement == right.replacement
    });
    edits
}

fn type_case_replacement(value: &str, policy: CapitalisationPolicy) -> Option<String> {
    match policy {
        CapitalisationPolicy::Consistent | CapitalisationPolicy::Lower => {
            Some(value.to_ascii_lowercase())
        }
        CapitalisationPolicy::Upper => Some(value.to_ascii_uppercase()),
        CapitalisationPolicy::Capitalise => Some(capitalise_ascii_token(value)),
        // These policies are currently report-only in CP05 autofix scope.
        CapitalisationPolicy::Pascal
        | CapitalisationPolicy::Camel
        | CapitalisationPolicy::Snake => None,
    }
}

fn capitalise_ascii_token(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut seen_alpha = false;

    for ch in value.chars() {
        if !ch.is_ascii_alphabetic() {
            out.push(ch);
            continue;
        }

        if !seen_alpha {
            out.push(ch.to_ascii_uppercase());
            seen_alpha = true;
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }

    out
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

fn source_word_matches(sql: &str, start: usize, end: usize, value: &str) -> bool {
    let Some(raw) = sql.get(start..end) else {
        return false;
    };
    let normalized = raw.trim_matches(|ch| matches!(ch, '"' | '`' | '[' | ']'));
    normalized.eq_ignore_ascii_case(value)
}

fn collect_user_defined_type_names(tokens: &[TokenWithSpan]) -> HashSet<String> {
    let mut out = HashSet::new();

    for index in 0..tokens.len() {
        let Token::Word(first) = &tokens[index].token else {
            continue;
        };
        let head = first.value.to_ascii_uppercase();
        if head != "CREATE" && head != "ALTER" {
            continue;
        }

        let Some(type_index) = next_non_trivia_index(tokens, index + 1) else {
            continue;
        };
        let Token::Word(type_word) = &tokens[type_index].token else {
            continue;
        };
        if !type_word.value.eq_ignore_ascii_case("TYPE") {
            continue;
        }

        let Some(name_index) = next_non_trivia_index(tokens, type_index + 1) else {
            continue;
        };
        let Token::Word(name_word) = &tokens[name_index].token else {
            continue;
        };
        out.insert(name_word.value.to_ascii_uppercase());
    }

    out
}

fn next_non_trivia_index(tokens: &[TokenWithSpan], mut index: usize) -> Option<usize> {
    while index < tokens.len() {
        match &tokens[index].token {
            Token::Whitespace(_) => index += 1,
            _ => return Some(index),
        }
    }
    None
}

fn is_tracked_type_name(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "INT"
            | "INTEGER"
            | "BIGINT"
            | "SMALLINT"
            | "TINYINT"
            | "VARCHAR"
            | "CHAR"
            | "TEXT"
            | "BOOLEAN"
            | "BOOL"
            | "STRING"
            | "INT64"
            | "FLOAT64"
            | "BYTES"
            | "DATE"
            | "TIME"
            | "TIMESTAMP"
            | "INTERVAL"
            | "NUMERIC"
            | "DECIMAL"
            | "FLOAT"
            | "DOUBLE"
            | "STRUCT"
            | "ARRAY"
            | "MAP"
            | "ENUM"
            | "WITH"
            | "ZONE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::config::LintConfig;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = CapitalisationTypes::default();
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
    fn flags_mixed_type_case() {
        let issues = run("CREATE TABLE t (a INT, b varchar(10))");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_005);
    }

    #[test]
    fn emits_safe_autofix_for_mixed_type_case() {
        let sql = "CREATE TABLE t (a INT, b varchar(10))";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "CREATE TABLE t (a int, b varchar(10))");
    }

    #[test]
    fn does_not_flag_consistent_type_case() {
        assert!(run("CREATE TABLE t (a int, b varchar(10))").is_empty());
    }

    #[test]
    fn does_not_flag_type_words_in_strings_or_comments() {
        let sql = "SELECT 'INT varchar BOOLEAN' AS txt -- INT varchar\nFROM t";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn upper_policy_flags_lowercase_type_name() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_005".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "upper"}),
            )]),
        };
        let rule = CapitalisationTypes::from_config(&config);
        let sql = "CREATE TABLE t (a int)";
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
    fn upper_policy_emits_uppercase_autofix() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_005".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "upper"}),
            )]),
        };
        let rule = CapitalisationTypes::from_config(&config);
        let sql = "CREATE TABLE t (a int)";
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
        assert_eq!(fixed, "CREATE TABLE t (a INT)");
    }

    #[test]
    fn camel_policy_violation_remains_report_only() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_005".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "camel"}),
            )]),
        };
        let rule = CapitalisationTypes::from_config(&config);
        let sql = "CREATE TABLE t (a INT)";
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
            "camel/pascal/snake are report-only in current CP005 autofix scope"
        );
    }

    #[test]
    fn ignore_words_regex_excludes_types_from_check() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_005".to_string(),
                serde_json::json!({"ignore_words_regex": "^varchar$"}),
            )]),
        };
        let rule = CapitalisationTypes::from_config(&config);
        let sql = "CREATE TABLE t (a INT, b varchar(10))";
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
