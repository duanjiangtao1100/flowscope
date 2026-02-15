//! LINT_AL_009: Self alias column.
//!
//! SQLFluff AL09 parity: avoid aliasing a column to its own name.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{Expr, Ident, SelectItem, Statement};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

use super::semantic_helpers::visit_selects_in_statement;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AliasCaseCheck {
    Dialect,
    CaseInsensitive,
    QuotedCsNakedUpper,
    QuotedCsNakedLower,
    CaseSensitive,
}

impl AliasCaseCheck {
    fn from_config(config: &LintConfig) -> Self {
        match config
            .rule_option_str(issue_codes::LINT_AL_009, "alias_case_check")
            .unwrap_or("dialect")
            .to_ascii_lowercase()
            .as_str()
        {
            "case_insensitive" => Self::CaseInsensitive,
            "quoted_cs_naked_upper" => Self::QuotedCsNakedUpper,
            "quoted_cs_naked_lower" => Self::QuotedCsNakedLower,
            "case_sensitive" => Self::CaseSensitive,
            _ => Self::Dialect,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct NameRef<'a> {
    name: &'a str,
    quoted: bool,
}

pub struct AliasingSelfAliasColumn {
    alias_case_check: AliasCaseCheck,
}

impl AliasingSelfAliasColumn {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            alias_case_check: AliasCaseCheck::from_config(config),
        }
    }
}

impl Default for AliasingSelfAliasColumn {
    fn default() -> Self {
        Self {
            alias_case_check: AliasCaseCheck::Dialect,
        }
    }
}

impl LintRule for AliasingSelfAliasColumn {
    fn code(&self) -> &'static str {
        issue_codes::LINT_AL_009
    }

    fn name(&self) -> &'static str {
        "Self alias column"
    }

    fn description(&self) -> &'static str {
        "Column aliases should not alias to itself, i.e. self-alias."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut violating_aliases = Vec::new();

        visit_selects_in_statement(statement, &mut |select| {
            for item in &select.projection {
                let SelectItem::ExprWithAlias { expr, alias } = item else {
                    continue;
                };

                if aliases_expression_to_itself(expr, alias, self.alias_case_check) {
                    violating_aliases.push(alias.clone());
                }
            }
        });
        let violation_count = violating_aliases.len();
        let mut autofix_candidates = al009_autofix_candidates_for_context(ctx, &violating_aliases);
        autofix_candidates.sort_by_key(|candidate| candidate.span.start);
        let candidates_align = autofix_candidates.len() == violation_count;

        (0..violation_count)
            .map(|index| {
                let mut issue = Issue::info(
                    issue_codes::LINT_AL_009,
                    "Column aliases should not alias to itself.",
                )
                .with_statement(ctx.statement_index);

                if candidates_align {
                    let candidate = &autofix_candidates[index];
                    issue = issue.with_span(candidate.span).with_autofix_edits(
                        IssueAutofixApplicability::Safe,
                        candidate.edits.clone(),
                    );
                }

                issue
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
struct PositionedToken {
    token: Token,
    start: usize,
    end: usize,
}

#[derive(Clone, Debug)]
struct Al009AutofixCandidate {
    span: Span,
    edits: Vec<IssuePatchEdit>,
}

fn al009_autofix_candidates_for_context(
    ctx: &LintContext,
    aliases: &[Ident],
) -> Vec<Al009AutofixCandidate> {
    if aliases.is_empty() {
        return Vec::new();
    }

    let tokens = statement_positioned_tokens(ctx);
    if tokens.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();

    for alias in aliases {
        let Some((alias_start, alias_end)) = ident_span_offsets(ctx.sql, alias) else {
            continue;
        };
        if alias_start < ctx.statement_range.start || alias_end > ctx.statement_range.end {
            continue;
        }

        let Some(alias_token_index) = tokens
            .iter()
            .position(|token| token.start == alias_start && token.end == alias_end)
        else {
            continue;
        };

        let Some(removal_span) = alias_removal_span(&tokens, alias_token_index) else {
            continue;
        };

        candidates.push(Al009AutofixCandidate {
            span: Span::new(alias_start, alias_end),
            edits: vec![IssuePatchEdit::new(removal_span, "")],
        });
    }

    candidates
}

fn statement_positioned_tokens(ctx: &LintContext) -> Vec<PositionedToken> {
    let from_document_tokens = ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        let mut positioned = Vec::new();
        for token in tokens {
            let (start, end) = token_with_span_offsets(ctx.sql, token)?;
            if start < ctx.statement_range.start || end > ctx.statement_range.end {
                continue;
            }

            positioned.push(PositionedToken {
                token: token.token.clone(),
                start,
                end,
            });
        }

        Some(positioned)
    });

    if let Some(tokens) = from_document_tokens {
        return tokens;
    }

    let dialect = ctx.dialect().to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), ctx.statement_sql());
    let Ok(tokens) = tokenizer.tokenize_with_location() else {
        return Vec::new();
    };

    let mut positioned = Vec::new();
    for token in &tokens {
        let Some((start, end)) = token_with_span_offsets(ctx.statement_sql(), token) else {
            continue;
        };
        positioned.push(PositionedToken {
            token: token.token.clone(),
            start: ctx.statement_range.start + start,
            end: ctx.statement_range.start + end,
        });
    }
    positioned
}

fn alias_removal_span(tokens: &[PositionedToken], alias_token_index: usize) -> Option<Span> {
    let alias = &tokens[alias_token_index];
    let previous_non_trivia = previous_non_trivia_index(tokens, alias_token_index)?;

    if token_is_as_keyword(&tokens[previous_non_trivia].token) {
        let expression_token = previous_non_trivia_index(tokens, previous_non_trivia)?;
        let gap_start = expression_token + 1;
        if gap_start > previous_non_trivia
            || trivia_contains_comment(tokens, gap_start, previous_non_trivia)
            || trivia_contains_comment(tokens, previous_non_trivia + 1, alias_token_index)
        {
            return None;
        }
        return Some(Span::new(tokens[gap_start].start, alias.end));
    }

    let gap_start = previous_non_trivia + 1;
    if gap_start >= alias_token_index
        || trivia_contains_comment(tokens, gap_start, alias_token_index)
    {
        return None;
    }

    Some(Span::new(tokens[gap_start].start, alias.end))
}

fn previous_non_trivia_index(tokens: &[PositionedToken], before: usize) -> Option<usize> {
    if before == 0 {
        return None;
    }

    let mut index = before - 1;
    loop {
        if !is_trivia(&tokens[index].token) {
            return Some(index);
        }
        if index == 0 {
            return None;
        }
        index -= 1;
    }
}

fn trivia_contains_comment(tokens: &[PositionedToken], start: usize, end: usize) -> bool {
    if start >= end {
        return false;
    }

    tokens[start..end].iter().any(|token| {
        matches!(
            token.token,
            Token::Whitespace(
                Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_)
            )
        )
    })
}

fn token_is_as_keyword(token: &Token) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case("AS"))
}

fn is_trivia(token: &Token) -> bool {
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

fn ident_span_offsets(sql: &str, ident: &Ident) -> Option<(usize, usize)> {
    let start = line_col_to_offset(
        sql,
        ident.span.start.line as usize,
        ident.span.start.column as usize,
    )?;
    let end = line_col_to_offset(
        sql,
        ident.span.end.line as usize,
        ident.span.end.column as usize,
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

fn aliases_expression_to_itself(
    expr: &Expr,
    alias: &Ident,
    alias_case_check: AliasCaseCheck,
) -> bool {
    let Some(source_name) = expression_name(expr) else {
        return false;
    };

    let alias_name = NameRef {
        name: alias.value.as_str(),
        quoted: alias.quote_style.is_some(),
    };

    names_match(source_name, alias_name, alias_case_check)
}

fn expression_name(expr: &Expr) -> Option<NameRef<'_>> {
    match expr {
        Expr::Identifier(identifier) => Some(NameRef {
            name: identifier.value.as_str(),
            quoted: identifier.quote_style.is_some(),
        }),
        Expr::CompoundIdentifier(parts) => parts.last().map(|part| NameRef {
            name: part.value.as_str(),
            quoted: part.quote_style.is_some(),
        }),
        Expr::Nested(inner) => expression_name(inner),
        _ => None,
    }
}

fn names_match(left: NameRef<'_>, right: NameRef<'_>, alias_case_check: AliasCaseCheck) -> bool {
    match alias_case_check {
        AliasCaseCheck::CaseInsensitive => left.name.eq_ignore_ascii_case(right.name),
        AliasCaseCheck::CaseSensitive => left.name == right.name,
        AliasCaseCheck::Dialect => {
            if left.quoted || right.quoted {
                left.name == right.name
            } else {
                left.name.eq_ignore_ascii_case(right.name)
            }
        }
        AliasCaseCheck::QuotedCsNakedUpper | AliasCaseCheck::QuotedCsNakedLower => {
            normalize_name_for_mode(left, alias_case_check)
                == normalize_name_for_mode(right, alias_case_check)
        }
    }
}

fn normalize_name_for_mode(name_ref: NameRef<'_>, mode: AliasCaseCheck) -> String {
    match mode {
        AliasCaseCheck::QuotedCsNakedUpper => {
            if name_ref.quoted {
                name_ref.name.to_string()
            } else {
                name_ref.name.to_ascii_uppercase()
            }
        }
        AliasCaseCheck::QuotedCsNakedLower => {
            if name_ref.quoted {
                name_ref.name.to_string()
            } else {
                name_ref.name.to_ascii_lowercase()
            }
        }
        _ => name_ref.name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = AliasingSelfAliasColumn::default();
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

    #[test]
    fn flags_plain_self_alias() {
        let issues = run("SELECT a AS a FROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_AL_009);
    }

    #[test]
    fn flags_qualified_self_alias() {
        let issues = run("SELECT t.a AS a FROM t");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn flags_case_insensitive_self_alias() {
        let issues = run("SELECT a AS A FROM t");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn does_not_flag_distinct_alias_name() {
        let issues = run("SELECT a AS b FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn does_not_flag_non_identifier_expression() {
        let issues = run("SELECT a + 1 AS a FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn default_dialect_mode_does_not_flag_quoted_case_mismatch() {
        let issues = run("SELECT \"A\" AS a FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn default_dialect_mode_flags_exact_quoted_match() {
        let issues = run("SELECT \"A\" AS \"A\" FROM t");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn alias_case_check_case_sensitive_respects_case() {
        let sql = "SELECT a AS A FROM t";
        let statements = parse_sql(sql).expect("parse");
        let rule = AliasingSelfAliasColumn::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.self_alias.column".to_string(),
                serde_json::json!({"alias_case_check": "case_sensitive"}),
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
    fn alias_case_check_quoted_cs_naked_upper_flags_upper_fold_match() {
        let sql = "SELECT \"FOO\" AS foo FROM t";
        let statements = parse_sql(sql).expect("parse");
        let rule = AliasingSelfAliasColumn::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.self_alias.column".to_string(),
                serde_json::json!({"alias_case_check": "quoted_cs_naked_upper"}),
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
    fn alias_case_check_quoted_cs_naked_upper_allows_nonmatching_quoted_case() {
        let sql = "SELECT \"foo\" AS foo FROM t";
        let statements = parse_sql(sql).expect("parse");
        let rule = AliasingSelfAliasColumn::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.self_alias.column".to_string(),
                serde_json::json!({"alias_case_check": "quoted_cs_naked_upper"}),
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
    fn alias_case_check_quoted_cs_naked_lower_flags_lower_fold_match() {
        let sql = "SELECT \"foo\" AS FOO FROM t";
        let statements = parse_sql(sql).expect("parse");
        let rule = AliasingSelfAliasColumn::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.self_alias.column".to_string(),
                serde_json::json!({"alias_case_check": "quoted_cs_naked_lower"}),
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
    fn alias_case_check_quoted_cs_naked_lower_allows_nonmatching_quoted_case() {
        let sql = "SELECT \"FOO\" AS FOO FROM t";
        let statements = parse_sql(sql).expect("parse");
        let rule = AliasingSelfAliasColumn::from_config(&LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.self_alias.column".to_string(),
                serde_json::json!({"alias_case_check": "quoted_cs_naked_lower"}),
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
    fn self_alias_with_as_emits_safe_autofix_patch() {
        let sql = "SELECT a AS a FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected AL009 core autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        let edit = &autofix.edits[0];
        assert_eq!(&sql[edit.span.start..edit.span.end], " AS a");
        assert_eq!(edit.replacement, "");
    }

    #[test]
    fn self_alias_without_as_emits_safe_autofix_patch() {
        let sql = "SELECT a a FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected AL009 core autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        let edit = &autofix.edits[0];
        assert_eq!(&sql[edit.span.start..edit.span.end], " a");
        assert_eq!(edit.replacement, "");
    }
}
