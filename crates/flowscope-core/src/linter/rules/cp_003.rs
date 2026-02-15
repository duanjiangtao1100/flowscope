//! LINT_CP_003: Function capitalisation.
//!
//! SQLFluff CP03 parity (current scope): detect inconsistent function name
//! capitalisation.

use std::collections::HashSet;

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use regex::Regex;
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

use super::capitalisation_policy_helpers::{
    ignored_words_from_config, ignored_words_regex_from_config, token_is_ignored,
    tokens_violate_policy, CapitalisationPolicy,
};

pub struct CapitalisationFunctions {
    policy: CapitalisationPolicy,
    ignore_words: HashSet<String>,
    ignore_words_regex: Option<Regex>,
}

impl CapitalisationFunctions {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            policy: CapitalisationPolicy::from_rule_config(
                config,
                issue_codes::LINT_CP_003,
                "extended_capitalisation_policy",
            ),
            ignore_words: ignored_words_from_config(config, issue_codes::LINT_CP_003),
            ignore_words_regex: ignored_words_regex_from_config(config, issue_codes::LINT_CP_003),
        }
    }
}

impl Default for CapitalisationFunctions {
    fn default() -> Self {
        Self {
            policy: CapitalisationPolicy::Consistent,
            ignore_words: HashSet::new(),
            ignore_words_regex: None,
        }
    }
}

impl LintRule for CapitalisationFunctions {
    fn code(&self) -> &'static str {
        issue_codes::LINT_CP_003
    }

    fn name(&self) -> &'static str {
        "Function capitalisation"
    }

    fn description(&self) -> &'static str {
        "Inconsistent capitalisation of function names."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let functions = function_candidates_for_context(
            ctx,
            &self.ignore_words,
            self.ignore_words_regex.as_ref(),
        );
        if functions.is_empty() {
            return Vec::new();
        }

        let function_tokens = functions
            .iter()
            .map(|candidate| candidate.value.clone())
            .collect::<Vec<_>>();
        if !tokens_violate_policy(&function_tokens, self.policy) {
            return Vec::new();
        }

        let mut issue = Issue::info(
            issue_codes::LINT_CP_003,
            "Function names use inconsistent capitalisation.",
        )
        .with_statement(ctx.statement_index);

        let autofix_edits = function_autofix_edits(ctx, &functions, self.policy);
        if !autofix_edits.is_empty() {
            issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, autofix_edits);
        }

        vec![issue]
    }
}

#[derive(Clone)]
struct FunctionCandidate {
    value: String,
    start: usize,
    end: usize,
}

fn function_candidates_for_context(
    ctx: &LintContext,
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> Vec<FunctionCandidate> {
    let sql = ctx.statement_sql();
    let Some(tokens) = tokenized(sql, ctx.dialect()) else {
        return Vec::new();
    };

    function_candidates(sql, &tokens, ignore_words, ignore_words_regex)
}

fn function_candidates(
    sql: &str,
    tokens: &[TokenWithSpan],
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> Vec<FunctionCandidate> {
    let mut out = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };

        if token_is_ignored(word.value.as_str(), ignore_words, ignore_words_regex) {
            continue;
        }

        let next_index = next_non_trivia_index(tokens, index + 1);
        let is_regular_function_call = next_index
            .map(|idx| matches!(tokens[idx].token, Token::LParen))
            .unwrap_or(false);
        let is_bare_function = is_bare_function_keyword(word.value.as_str());
        if !is_regular_function_call && !is_bare_function {
            continue;
        }

        let Some((start, end)) = token_offsets(sql, token) else {
            continue;
        };

        out.push(FunctionCandidate {
            value: word.value.clone(),
            start,
            end,
        });
    }

    out
}

fn function_autofix_edits(
    ctx: &LintContext,
    functions: &[FunctionCandidate],
    policy: CapitalisationPolicy,
) -> Vec<IssuePatchEdit> {
    let mut edits = Vec::new();

    for candidate in functions {
        let Some(replacement) = function_case_replacement(candidate.value.as_str(), policy) else {
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

fn function_case_replacement(value: &str, policy: CapitalisationPolicy) -> Option<String> {
    match policy {
        CapitalisationPolicy::Consistent | CapitalisationPolicy::Lower => {
            Some(value.to_ascii_lowercase())
        }
        CapitalisationPolicy::Upper => Some(value.to_ascii_uppercase()),
        CapitalisationPolicy::Capitalise => Some(capitalise_ascii_token(value)),
        // These policies are currently report-only in CP03 autofix scope.
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

fn is_bare_function_keyword(value: &str) -> bool {
    matches!(
        value.to_ascii_uppercase().as_str(),
        "CURRENT_TIMESTAMP" | "CURRENT_DATE" | "CURRENT_TIME" | "LOCALTIME" | "LOCALTIMESTAMP"
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
        let rule = CapitalisationFunctions::default();
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
    fn flags_mixed_function_case() {
        let issues = run("SELECT COUNT(*), count(x) FROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_003);
    }

    #[test]
    fn emits_safe_autofix_for_mixed_function_case() {
        let sql = "SELECT COUNT(*), count(x) FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT count(*), count(x) FROM t");
    }

    #[test]
    fn does_not_flag_consistent_function_case() {
        assert!(run("SELECT lower(x), upper(y) FROM t").is_empty());
    }

    #[test]
    fn does_not_flag_function_like_text_in_strings_or_comments() {
        let sql = "SELECT 'COUNT(x) count(y)' AS txt -- COUNT(x)\nFROM t";
        assert!(run(sql).is_empty());
    }

    #[test]
    fn lower_policy_flags_uppercase_function_name() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_003".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "lower"}),
            )]),
        };
        let rule = CapitalisationFunctions::from_config(&config);
        let sql = "SELECT COUNT(x) FROM t";
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
                "LINT_CP_003".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "upper"}),
            )]),
        };
        let rule = CapitalisationFunctions::from_config(&config);
        let sql = "SELECT count(x) FROM t";
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
        assert_eq!(fixed, "SELECT COUNT(x) FROM t");
    }

    #[test]
    fn camel_policy_violation_remains_report_only() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_003".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "camel"}),
            )]),
        };
        let rule = CapitalisationFunctions::from_config(&config);
        let sql = "SELECT COUNT(x) FROM t";
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
            "camel/pascal/snake are report-only in current CP003 autofix scope"
        );
    }

    #[test]
    fn ignore_words_regex_excludes_functions_from_check() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CP_003".to_string(),
                serde_json::json!({"ignore_words_regex": "^count$"}),
            )]),
        };
        let rule = CapitalisationFunctions::from_config(&config);
        let sql = "SELECT COUNT(*), count(x) FROM t";
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

    #[test]
    fn bare_function_keywords_are_tracked() {
        let issues = run("SELECT CURRENT_TIMESTAMP, current_timestamp FROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_003);
    }
}
