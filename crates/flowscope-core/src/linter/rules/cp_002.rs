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
use super::identifier_candidates_helpers::{
    collect_identifier_candidates, IdentifierKind, IdentifierPolicy,
};

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
            statement,
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
    statement: &Statement,
) -> Vec<Cp002AutofixEdit> {
    let Some(tokens) = tokenized(sql, dialect) else {
        return Vec::new();
    };

    // Collect AST-level identifier candidates. Used for:
    // 1. Alias-only policies: only fix identifiers that match the policy filter.
    // 2. All policies: allow keyword-classified tokens through when they match
    //    AST identifiers (e.g. SHOW TBLPROPERTIES property names).
    let all_candidates = collect_identifier_candidates(statement);
    let ast_ident_set: HashSet<String> = all_candidates
        .iter()
        .filter(|c| !c.quoted)
        .filter(|c| !token_is_ignored(&c.value, ignore_words, ignore_words_regex))
        .map(|c| c.value.clone())
        .collect();

    // For alias-only policies, build the set of alias values that match the
    // policy filter (column aliases, table aliases, or both).
    // Additionally, build a set of column-alias-only and table-alias-only
    // values to distinguish them when a value appears as both types.
    let alias_set: Option<HashSet<String>> = if unquoted_policy != IdentifierPolicy::All {
        let names: HashSet<String> = all_candidates
            .iter()
            .filter(|c| !c.quoted && unquoted_policy.allows(c.kind))
            .filter(|c| !token_is_ignored(&c.value, ignore_words, ignore_words_regex))
            .map(|c| c.value.clone())
            .collect();
        Some(names)
    } else {
        None
    };

    // Build a per-value sequence of alias kinds from the AST (in order of
    // appearance) for position-based disambiguation.
    // E.g., if `lower_case` appears as ColumnAlias then TableAlias, we get:
    //   alias_kind_seq["lower_case"] = [ColumnAlias, TableAlias]
    let alias_kind_seq: std::collections::HashMap<String, Vec<IdentifierKind>> = {
        let mut seq: std::collections::HashMap<String, Vec<IdentifierKind>> =
            std::collections::HashMap::new();
        for c in &all_candidates {
            if c.quoted || token_is_ignored(&c.value, ignore_words, ignore_words_regex) {
                continue;
            }
            if matches!(
                c.kind,
                IdentifierKind::ColumnAlias | IdentifierKind::TableAlias
            ) {
                seq.entry(c.value.clone()).or_default().push(c.kind);
            }
        }
        seq
    };
    // Track per-value occurrence counters during the token scan.
    let mut alias_occurrence_counters: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    // Resolve the effective policy: for Consistent, determine the concrete
    // target case using SQLFluff's refutation algorithm.
    // When an alias-only policy is active, only consider tokens in alias
    // position (after AS keyword) for the consistent resolution.
    let effective_policy = if policy == CapitalisationPolicy::Consistent {
        if alias_set.is_some() {
            resolve_consistent_policy_alias_only(&tokens, ignore_words, ignore_words_regex)
        } else {
            resolve_consistent_policy(&tokens, ignore_words, ignore_words_regex, &ast_ident_set)
        }
    } else {
        policy
    };

    let mut edits = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() {
            continue;
        }
        // Skip words that are SQL keywords (not identifiers) unless they
        // appear in the AST-level identifier set (e.g. SHOW TBLPROPERTIES
        // property names that the tokenizer classifies as keywords but the
        // AST recognizes as identifiers).
        if word.keyword != Keyword::NoKeyword && !ast_ident_set.contains(&word.value) {
            continue;
        }
        if token_is_ignored(word.value.as_str(), ignore_words, ignore_words_regex) {
            continue;
        }

        // For alias-only policies, only fix tokens that are in alias
        // position (after AS keyword) to avoid modifying non-alias references
        // that happen to share the same name.
        if alias_set.is_some() {
            let prev_non_trivia = prev_non_trivia_index(&tokens, index);
            let is_after_as = prev_non_trivia
                .map(|pi| {
                    matches!(
                        &tokens[pi].token,
                        Token::Word(w) if w.keyword == Keyword::AS
                    )
                })
                .unwrap_or(false);
            if !is_after_as {
                continue;
            }
            // Disambiguate column vs table aliases using the AST-derived
            // alias kind sequence. For each after-AS occurrence of a value,
            // look up its n-th alias kind from the AST to determine whether
            // this specific occurrence is a column alias or table alias.
            let val = &word.value;
            let occurrence = alias_occurrence_counters.entry(val.clone()).or_insert(0);
            let kind = alias_kind_seq
                .get(val)
                .and_then(|kinds| kinds.get(*occurrence))
                .copied();
            *alias_occurrence_counters.get_mut(val).unwrap() += 1;
            match kind {
                Some(k) if !unquoted_policy.allows(k) => continue,
                None => continue,
                _ => {}
            }
        }

        let next_index = next_non_trivia_index(&tokens, index + 1);
        let is_function_name = next_index
            .map(|next| matches!(tokens[next].token, Token::LParen))
            .unwrap_or(false);
        if is_function_name {
            continue;
        }

        let Some(replacement) = identifier_case_replacement(word.value.as_str(), effective_policy)
        else {
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
        CapitalisationPolicy::Lower => Some(value.to_ascii_lowercase()),
        CapitalisationPolicy::Upper => Some(value.to_ascii_uppercase()),
        CapitalisationPolicy::Capitalise => Some(capitalise_ascii_token(value)),
        CapitalisationPolicy::Pascal => Some(pascal_case(value)),
        CapitalisationPolicy::Camel => Some(camel_case(value)),
        CapitalisationPolicy::Snake => Some(snake_case(value)),
        // Consistent should be resolved to a concrete policy before calling
        // this function; if somehow it reaches here, fall back to lower.
        CapitalisationPolicy::Consistent => Some(value.to_ascii_lowercase()),
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

/// SQLFluff pascal-case fix: uppercase the first letter of each "word" (split
/// at non-alphanumeric boundaries or at string start), leave other chars as-is.
fn pascal_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut at_word_start = true;
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() {
            out.push(ch);
            at_word_start = true;
        } else if at_word_start {
            out.push(ch.to_ascii_uppercase());
            at_word_start = false;
        } else {
            out.push(ch);
            at_word_start = false;
        }
    }
    out
}

/// SQLFluff camel-case fix: lowercase the first letter of each "word" (split
/// at non-alphanumeric boundaries or at string start), leave other chars as-is.
fn camel_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut at_word_start = true;
    for ch in value.chars() {
        if !ch.is_ascii_alphanumeric() {
            out.push(ch);
            at_word_start = true;
        } else if at_word_start {
            out.push(ch.to_ascii_lowercase());
            at_word_start = false;
        } else {
            out.push(ch);
            at_word_start = false;
        }
    }
    out
}

/// Convert an identifier to snake_case matching SQLFluff's multi-pass behavior.
///
/// SQLFluff applies fixes iteratively: pass 1 lowercases all-uppercase tokens,
/// pass 2 inserts underscores at letter/digit boundaries in the now-lowercase
/// result. We produce the equivalent final output in a single pass by always
/// inserting underscores at camelCase boundaries AND letter/digit boundaries,
/// then lowercasing.
fn snake_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    let chars: Vec<char> = value.chars().collect();
    let all_upper = chars
        .iter()
        .filter(|c| c.is_ascii_alphabetic())
        .all(|c| c.is_ascii_uppercase());
    for (i, &ch) in chars.iter().enumerate() {
        if i > 0 {
            let prev = chars[i - 1];
            if !all_upper {
                // Upper after lower/digit: insert underscore
                if ch.is_ascii_uppercase() && (prev.is_ascii_lowercase() || prev.is_ascii_digit()) {
                    out.push('_');
                }
            }
            // Digit after letter: insert underscore
            if ch.is_ascii_digit() && prev.is_ascii_alphabetic() {
                out.push('_');
            }
            // Letter after digit: insert underscore
            if ch.is_ascii_alphabetic() && prev.is_ascii_digit() {
                out.push('_');
            }
        }
        out.push(ch);
    }
    out.to_ascii_lowercase()
}

/// Resolve the "consistent" policy to a concrete case by scanning identifier
/// tokens and using SQLFluff's refutation algorithm.
///
/// For each identifier, we eliminate case styles that are incompatible:
///   - camel, pascal, snake are always pre-refuted (never inferred)
///   - first letter lowercase -> refute upper, capitalise
///   - first letter lowercase && mixed -> refute lower
///   - first letter uppercase -> refute lower
///   - not all uppercase -> refute upper
///   - not capitalize() -> refute capitalise
///
/// Priority order (matching SQLFluff): upper, lower, capitalise.
/// If all are refuted, falls back to the latest possible case, or "upper".
/// `relevant_idents` controls which tokens participate in refutation.
/// For the "all" unquoted policy this is the full AST identifier set.
/// For alias-only policies this is only the alias identifier values.
fn resolve_consistent_policy(
    tokens: &[TokenWithSpan],
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
    relevant_idents: &HashSet<String>,
) -> CapitalisationPolicy {
    const UPPER: u8 = 0b001;
    const LOWER: u8 = 0b010;
    const CAPITALISE: u8 = 0b100;

    let mut refuted: u8 = 0;
    let mut latest_possible = CapitalisationPolicy::Upper; // default fallback

    for token in tokens {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() {
            continue;
        }
        // Only consider tokens whose value appears in the relevant set.
        if !relevant_idents.contains(&word.value) {
            continue;
        }
        if token_is_ignored(word.value.as_str(), ignore_words, ignore_words_regex) {
            continue;
        }

        let raw = &word.value;

        // Determine if the first capitalizable character is lowercase.
        let first_is_lower = raw
            .chars()
            .find(|c| c.to_ascii_lowercase() != c.to_ascii_uppercase())
            .is_some_and(|c| c != c.to_ascii_uppercase());

        if first_is_lower {
            refuted |= UPPER | CAPITALISE;
            if raw.as_str() != raw.to_ascii_lowercase() {
                refuted |= LOWER;
            }
        } else {
            refuted |= LOWER;
            if raw.as_str() != raw.to_ascii_uppercase() {
                refuted |= UPPER;
            }
            if raw.as_str() != capitalize_str(raw) {
                refuted |= CAPITALISE;
            }
        }

        // Track latest possible case before full refutation.
        let possible = !refuted;
        if possible & UPPER != 0 {
            latest_possible = CapitalisationPolicy::Upper;
        } else if possible & LOWER != 0 {
            latest_possible = CapitalisationPolicy::Lower;
        } else if possible & CAPITALISE != 0 {
            latest_possible = CapitalisationPolicy::Capitalise;
        }

        // If all refuted, we already have the answer.
        if refuted == (UPPER | LOWER | CAPITALISE) {
            break;
        }
    }

    if refuted != (UPPER | LOWER | CAPITALISE) {
        // Still consistent — pick the first non-refuted case.
        if refuted & UPPER == 0 {
            return CapitalisationPolicy::Upper;
        }
        if refuted & LOWER == 0 {
            return CapitalisationPolicy::Lower;
        }
        return CapitalisationPolicy::Capitalise;
    }

    latest_possible
}

/// Python-compatible str.capitalize(): first char uppercased, rest lowercased.
fn capitalize_str(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            let mut out = String::with_capacity(s.len());
            for c in first.to_uppercase() {
                out.push(c);
            }
            for c in chars {
                out.push(c.to_ascii_lowercase());
            }
            out
        }
    }
}

/// Like `resolve_consistent_policy` but only considers tokens that appear
/// immediately after an AS keyword (alias position).
fn resolve_consistent_policy_alias_only(
    tokens: &[TokenWithSpan],
    ignore_words: &HashSet<String>,
    ignore_words_regex: Option<&Regex>,
) -> CapitalisationPolicy {
    const UPPER: u8 = 0b001;
    const LOWER: u8 = 0b010;
    const CAPITALISE: u8 = 0b100;

    let mut refuted: u8 = 0;
    let mut latest_possible = CapitalisationPolicy::Upper;

    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.quote_style.is_some() {
            continue;
        }
        // Only consider tokens in alias position (after AS keyword).
        let prev = prev_non_trivia_index(tokens, index);
        let is_after_as = prev
            .map(|pi| {
                matches!(
                    &tokens[pi].token,
                    Token::Word(w) if w.keyword == Keyword::AS
                )
            })
            .unwrap_or(false);
        if !is_after_as {
            continue;
        }
        if token_is_ignored(word.value.as_str(), ignore_words, ignore_words_regex) {
            continue;
        }

        let raw = &word.value;
        let first_is_lower = raw
            .chars()
            .find(|c| c.to_ascii_lowercase() != c.to_ascii_uppercase())
            .is_some_and(|c| c != c.to_ascii_uppercase());

        if first_is_lower {
            refuted |= UPPER | CAPITALISE;
            if raw.as_str() != raw.to_ascii_lowercase() {
                refuted |= LOWER;
            }
        } else {
            refuted |= LOWER;
            if raw.as_str() != raw.to_ascii_uppercase() {
                refuted |= UPPER;
            }
            if raw.as_str() != capitalize_str(raw) {
                refuted |= CAPITALISE;
            }
        }

        let possible = !refuted;
        if possible & UPPER != 0 {
            latest_possible = CapitalisationPolicy::Upper;
        } else if possible & LOWER != 0 {
            latest_possible = CapitalisationPolicy::Lower;
        } else if possible & CAPITALISE != 0 {
            latest_possible = CapitalisationPolicy::Capitalise;
        }

        if refuted == (UPPER | LOWER | CAPITALISE) {
            break;
        }
    }

    if refuted != (UPPER | LOWER | CAPITALISE) {
        if refuted & UPPER == 0 {
            return CapitalisationPolicy::Upper;
        }
        if refuted & LOWER == 0 {
            return CapitalisationPolicy::Lower;
        }
        return CapitalisationPolicy::Capitalise;
    }

    latest_possible
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

fn prev_non_trivia_index(tokens: &[TokenWithSpan], index: usize) -> Option<usize> {
    let mut i = index;
    while i > 0 {
        i -= 1;
        if !is_trivia_token(&tokens[i].token) {
            return Some(i);
        }
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
        // Col refutes lower and upper, leaving capitalise. col then violates
        // capitalise, so the consistent policy resolves to capitalise.
        let sql = "SELECT Col, col FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT Col, Col FROM T");
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
        let sql = "SELECT amount AS Col, amount AS col FROM t";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CP_002);
        // With column_aliases policy, autofix targets only column alias tokens.
        // Col refutes lower/upper, leaving capitalise. col violates -> capitalise.
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT amount AS Col, amount AS Col FROM t");
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

    // -- SQLFluff parity: consistent policy direction --

    #[test]
    fn consistent_resolves_to_upper_when_pascal_refutes_capitalise() {
        // AppleFritter refutes lower, upper, capitalise -> all refuted.
        // latest_possible starts at upper (no lower tokens seen first).
        let sql = "SELECT AppleFritter, Banana";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT APPLEFRITTER, BANANA");
    }

    #[test]
    fn consistent_resolves_to_upper_for_mixed_with_numbers() {
        let sql = "SELECT AppleFritter, Apple123fritter, Apple123Fritter";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(
            fixed,
            "SELECT APPLEFRITTER, APPLE123FRITTER, APPLE123FRITTER"
        );
    }

    #[test]
    fn consistent_resolves_to_lower_when_lowercase_first() {
        // a is lowercase -> refute upper, capitalise. B then violates.
        let sql = "SELECT a FROM FOO";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a FROM foo");
    }

    #[test]
    fn consistent_resolves_to_upper_when_uppercase_first() {
        // B is upper -> refute lower. a then violates.
        let sql = "SELECT B, a FROM foo";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT B, A FROM FOO");
    }

    // -- SQLFluff parity: pascal autofix --

    #[test]
    fn pascal_policy_fixes_lowercase_to_pascal() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "pascal"}),
            )]),
        };
        let sql = "SELECT pascalcase";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT Pascalcase");
    }

    #[test]
    fn pascal_policy_fixes_underscored_to_pascal() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "pascal"}),
            )]),
        };
        let sql = "SELECT pascal_case";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT Pascal_Case");
    }

    #[test]
    fn pascal_policy_fixes_upperfirst_underscored() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "pascal"}),
            )]),
        };
        // pASCAL_CASE -> PASCAL_CASE (uppercase first letter of each word)
        let sql = "SELECT pASCAL_CASE";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT PASCAL_CASE");
    }

    #[test]
    fn pascal_policy_fixes_pascal_v_capitalise() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "pascal"}),
            )]),
        };
        let sql = "SELECT AppleFritter, Banana_split";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT AppleFritter, Banana_Split");
    }

    // -- SQLFluff parity: camel autofix --

    #[test]
    fn camel_policy_fixes_capitalised_to_camel() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "camel"}),
            )]),
        };
        let sql = "SELECT Camelcase";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT camelcase");
    }

    #[test]
    fn camel_policy_fixes_underscored_to_camel() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "camel"}),
            )]),
        };
        let sql = "SELECT Camel_Case";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT camel_case");
    }

    #[test]
    fn camel_policy_fixes_partial_upper() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "camel"}),
            )]),
        };
        let sql = "SELECT cAMEL_CASE";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT cAMEL_cASE");
    }

    // -- SQLFluff parity: snake autofix --

    #[test]
    fn snake_policy_fixes_camel_to_snake() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "snake"}),
            )]),
        };
        let sql = "SELECT testColumn3";
        let issues = run_with_config_in_dialect(sql, Dialect::Mssql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT test_column_3");
    }

    #[test]
    fn snake_policy_fixes_all_upper_to_lower() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"extended_capitalisation_policy": "snake"}),
            )]),
        };
        let sql = "SELECT TESTCOLUMN5";
        let issues = run_with_config_in_dialect(sql, Dialect::Mssql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT testcolumn_5");
    }

    // -- SQLFluff parity: alias-only autofix --

    #[test]
    fn aliases_policy_fixes_only_aliases() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "capitalisation.identifiers".to_string(),
                serde_json::json!({"unquoted_identifiers_policy": "aliases"}),
            )]),
        };
        // low_case appears twice -> lower is consistent for aliases.
        // Table alias UPPER_CASE violates -> fix to lowercase.
        let sql =
            "SELECT UPPER_CASE AS low_case, PascalCase AS low_case FROM UPPER_CASE AS UPPER_CASE";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(
            fixed,
            "SELECT UPPER_CASE AS low_case, PascalCase AS low_case FROM UPPER_CASE AS upper_case"
        );
    }

    // -- SQLFluff parity: TBLPROPERTIES autofix --

    #[test]
    fn sparksql_tblproperties_autofix_lowercases() {
        let sql = "SHOW TBLPROPERTIES customer (created.BY.user)";
        let issues = run_with_config_in_dialect(sql, Dialect::Databricks, LintConfig::default());
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert!(!autofix.edits.is_empty(), "should emit autofix edits");
    }
}
