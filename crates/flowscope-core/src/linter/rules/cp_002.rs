//! LINT_CP_002: Identifier capitalisation.
//!
//! SQLFluff CP02 parity (current scope): detect inconsistent identifier case.

use std::collections::HashSet;

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use regex::Regex;
use sqlparser::ast::Statement;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

use super::capitalisation_policy_helpers::{
    ignored_words_from_config, ignored_words_regex_from_config, token_is_ignored,
    tokens_violate_policy, CapitalisationPolicy,
};
use super::identifier_candidates_helpers::{collect_identifier_candidates, IdentifierPolicy};

pub struct CapitalisationIdentifiers {
    policy: CapitalisationPolicy,
    unquoted_policy: IdentifierPolicy,
    ignore_words: HashSet<String>,
    ignore_words_regex: Option<Regex>,
}

impl CapitalisationIdentifiers {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            policy: CapitalisationPolicy::from_rule_config(
                config,
                issue_codes::LINT_CP_002,
                "extended_capitalisation_policy",
            ),
            unquoted_policy: IdentifierPolicy::from_config(
                config,
                issue_codes::LINT_CP_002,
                "unquoted_identifiers_policy",
                "all",
            ),
            ignore_words: ignored_words_from_config(config, issue_codes::LINT_CP_002),
            ignore_words_regex: ignored_words_regex_from_config(config, issue_codes::LINT_CP_002),
        }
    }
}

impl Default for CapitalisationIdentifiers {
    fn default() -> Self {
        Self {
            policy: CapitalisationPolicy::Consistent,
            unquoted_policy: IdentifierPolicy::All,
            ignore_words: HashSet::new(),
            ignore_words_regex: None,
        }
    }
}

impl LintRule for CapitalisationIdentifiers {
    fn code(&self) -> &'static str {
        issue_codes::LINT_CP_002
    }

    fn name(&self) -> &'static str {
        "Identifier capitalisation"
    }

    fn description(&self) -> &'static str {
        "Inconsistent capitalisation of unquoted identifiers."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let identifiers = identifier_tokens(
            statement,
            self.unquoted_policy,
            &self.ignore_words,
            self.ignore_words_regex.as_ref(),
        );
        if !tokens_violate_policy(&identifiers, self.policy) {
            return Vec::new();
        }

        let mut issue = Issue::info(
            issue_codes::LINT_CP_002,
            "Identifiers use inconsistent capitalisation.",
        )
        .with_statement(ctx.statement_index);

        let autofix_edits = identifier_autofix_edits(
            ctx.statement_sql(),
            ctx.dialect(),
            self.policy,
            self.unquoted_policy,
            &self.ignore_words,
            self.ignore_words_regex.as_ref(),
        )
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
    }
}

fn identifier_tokens(
    statement: &Statement,
    unquoted_policy: IdentifierPolicy,
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> Vec<String> {
    collect_identifier_candidates(statement)
        .into_iter()
        .filter_map(|candidate| {
            if candidate.quoted || !unquoted_policy.allows(candidate.kind) {
                return None;
            }

            if token_is_ignored(candidate.value.as_str(), ignore_words, ignore_words_regex) {
                return None;
            }

            Some(candidate.value)
        })
        .collect()
}

struct Cp002AutofixEdit {
    start: usize,
    end: usize,
    replacement: String,
}

fn identifier_autofix_edits(
    sql: &str,
    dialect: Dialect,
    policy: CapitalisationPolicy,
    unquoted_policy: IdentifierPolicy,
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> Vec<Cp002AutofixEdit> {
    if unquoted_policy != IdentifierPolicy::All {
        return Vec::new();
    }

    let Some(tokens) = tokenized(sql, dialect) else {
        return Vec::new();
    };

    let mut edits = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() || word.keyword != Keyword::NoKeyword {
            continue;
        }
        if token_is_ignored(word.value.as_str(), ignore_words, ignore_words_regex) {
            continue;
        }

        let next_index = next_non_trivia_index(&tokens, index + 1);
        let is_function_name = next_index
            .map(|next| matches!(tokens[next].token, Token::LParen))
            .unwrap_or(false);
        if is_function_name {
            continue;
        }

        let Some(replacement) = identifier_case_replacement(word.value.as_str(), policy) else {
            continue;
        };
        if replacement == word.value {
            continue;
        }

        let Some((start, end)) = token_offsets(sql, token) else {
            continue;
        };
        edits.push(Cp002AutofixEdit {
            start,
            end,
            replacement,
        });
    }

    edits
}

fn identifier_case_replacement(value: &str, policy: CapitalisationPolicy) -> Option<String> {
    match policy {
        CapitalisationPolicy::Consistent | CapitalisationPolicy::Lower => {
            Some(value.to_ascii_lowercase())
        }
        CapitalisationPolicy::Upper => Some(value.to_ascii_uppercase()),
        CapitalisationPolicy::Capitalise => Some(capitalise_ascii_token(value)),
        // These policies are currently report-only in CP02 autofix scope.
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

fn tokenized(sql: &str, dialect: Dialect) -> Option<Vec<TokenWithSpan>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    tokenizer.tokenize_with_location().ok()
}

fn next_non_trivia_index(tokens: &[TokenWithSpan], mut index: usize) -> Option<usize> {
    while index < tokens.len() {
        if !is_trivia_token(&tokens[index].token) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn is_trivia_token(token: &Token) -> bool {
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

fn token_offsets(sql: &str, token: &TokenWithSpan) -> Option<(usize, usize)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::config::LintConfig;
    use crate::parser::parse_sql_with_dialect;
    use crate::types::Dialect;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        run_with_config(sql, LintConfig::default())
    }

    fn run_with_config(sql: &str, config: LintConfig) -> Vec<Issue> {
        run_with_config_in_dialect(sql, Dialect::Generic, config)
    }

    fn run_with_config_in_dialect(sql: &str, dialect: Dialect, config: LintConfig) -> Vec<Issue> {
        let statements = parse_sql_with_dialect(sql, dialect).expect("parse");
        let rule = CapitalisationIdentifiers::from_config(&config);
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
    fn flags_mixed_identifier_case() {
        let sql = "SELECT Col, col FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT col, col FROM t");
    }

    #[test]
    fn does_not_flag_consistent_identifiers() {
        assert!(run("SELECT col_one, col_two FROM t").is_empty());
    }

    #[test]
    fn does_not_flag_identifier_like_words_in_strings_or_comments() {
        let sql = "SELECT 'Col col' AS txt -- Col col\nFROM t";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn upper_policy_flags_lowercase_identifier() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "upper"}),
            )]),
        };
        let issues = run_with_config("SELECT col FROM t", config);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn uppercase_policy_emits_uppercase_autofix() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "upper"}),
            )]),
        };
        let sql = "SELECT col FROM t";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT COL FROM T");
    }

    #[test]
    fn ignore_words_regex_excludes_identifiers_from_check() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"ignore_words_regex": "^col$"}),
            )]),
        };
        let issues = run_with_config("SELECT Col, col FROM t", config);
        assert!(issues.is_empty());
    }

    #[test]
    fn aliases_policy_ignores_non_alias_identifiers() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"unquoted_identifiers_policy": "aliases"}),
            )]),
        };
        let issues = run_with_config("SELECT Col AS alias FROM t", config);
        assert!(issues.is_empty());
    }

    #[test]
    fn column_alias_policy_flags_mixed_column_alias_case() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_002".to_string(),
                serde_json::json!({"unquoted_identifiers_policy": "column_aliases"}),
            )]),
        };
        let issues = run_with_config("SELECT amount AS Col, amount AS col FROM t", config);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
        assert!(
            issues[0].autofix.is_none(),
            "non-default unquoted identifier policies remain report-only in current CP002 migration"
        );
    }

    #[test]
    fn consistent_policy_allows_single_letter_upper_with_capitalised_identifier() {
        let issues = run("SELECT A, Boo");
        assert!(issues.is_empty());
    }

    #[test]
    fn pascal_policy_allows_all_caps_identifier() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "pascal"}),
            )]),
        };
        let issues = run_with_config("SELECT PASCALCASE", config);
        assert!(issues.is_empty());
    }

    #[test]
    fn databricks_tblproperties_mixed_case_property_is_flagged() {
        let issues = run_with_config_in_dialect(
            "SHOW TBLPROPERTIES customer (created.BY.user)",
            Dialect::Databricks,
            LintConfig::default(),
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
    }

    #[test]
    fn databricks_tblproperties_lowercase_property_is_allowed() {
        let issues = run_with_config_in_dialect(
            "SHOW TBLPROPERTIES customer (created.by.user)",
            Dialect::Databricks,
            LintConfig::default(),
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn databricks_tblproperties_capitalised_property_is_flagged() {
        let issues = run_with_config_in_dialect(
            "SHOW TBLPROPERTIES customer (Created.By.User)",
            Dialect::Databricks,
            LintConfig::default(),
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
    }

    #[test]
    fn flags_mixed_identifier_case_in_delete_predicate() {
        let issues = run("DELETE FROM t WHERE Col = col");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
    }

    #[test]
    fn flags_mixed_identifier_case_in_update_assignment() {
        let issues = run("UPDATE t SET Col = col");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
    }
}
