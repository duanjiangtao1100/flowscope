//! LINT_LT_012: Layout end of file.
//!
//! SQLFluff LT12 parity (current scope): SQL text should end with exactly one
//! trailing newline.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct LayoutEndOfFile;

impl LintRule for LayoutEndOfFile {
    fn code(&self) -> &'static str {
        issue_codes::LINT_LT_012
    }

    fn name(&self) -> &'static str {
        "Layout end of file"
    }

    fn description(&self) -> &'static str {
        "Files must end with a single trailing newline."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let content_end = ctx
            .sql
            .trim_end_matches(|ch: char| ch.is_ascii_whitespace())
            .len();
        let is_last_statement = ctx.statement_range.end >= content_end;
        let trailing_newlines = trailing_newline_count_tokenized(ctx);
        let has_violation = is_last_statement && trailing_newlines != 1;

        if has_violation {
            let trailing_span = Span::new(content_end, ctx.sql.len());
            vec![Issue::info(
                issue_codes::LINT_LT_012,
                "SQL document should end with a single trailing newline.",
            )
            .with_statement(ctx.statement_index)
            .with_span(trailing_span)
            .with_autofix_edits(
                IssueAutofixApplicability::Safe,
                vec![IssuePatchEdit::new(trailing_span, "\n")],
            )]
        } else {
            Vec::new()
        }
    }
}

#[derive(Clone)]
struct LocatedToken {
    token: Token,
    end: usize,
}

fn trailing_newline_count_tokenized(ctx: &LintContext) -> usize {
    let tokens = tokenize_with_offsets_for_context(ctx)
        .or_else(|| tokenize_with_offsets(ctx.sql, ctx.dialect()))
        .unwrap_or_default();
    let content_end = tokens
        .iter()
        .rev()
        .find(|token| !is_whitespace_token(&token.token))
        .map_or(0, |token| token.end);
    trailing_newline_count(&ctx.sql[content_end..])
}

fn tokenize_with_offsets(sql: &str, dialect: Dialect) -> Option<Vec<LocatedToken>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let tokens = tokenizer.tokenize_with_location().ok()?;

    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let Some(end) = line_col_to_offset(
            sql,
            token.span.end.line as usize,
            token.span.end.column as usize,
        ) else {
            continue;
        };
        out.push(LocatedToken {
            token: token.token,
            end,
        });
    }
    Some(out)
}

fn tokenize_with_offsets_for_context(ctx: &LintContext) -> Option<Vec<LocatedToken>> {
    ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        Some(
            tokens
                .iter()
                .filter_map(|token| {
                    token_with_span_offsets(ctx.sql, token).map(|(_start, end)| LocatedToken {
                        token: token.token.clone(),
                        end,
                    })
                })
                .collect(),
        )
    })
}

fn is_whitespace_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
    )
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

fn trailing_newline_count(sql: &str) -> usize {
    sql.chars()
        .rev()
        .take_while(|ch| *ch == '\n' || *ch == '\r')
        .filter(|ch| *ch == '\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = LayoutEndOfFile;
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
        let mut edits = autofix.edits.clone();
        edits.sort_by(|left, right| right.span.start.cmp(&left.span.start));

        let mut out = sql.to_string();
        for edit in edits {
            out.replace_range(edit.span.start..edit.span.end, &edit.replacement);
        }
        Some(out)
    }

    #[test]
    fn flags_missing_trailing_newline() {
        let sql = "SELECT 1\nFROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_012);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 1\nFROM t\n");
    }

    #[test]
    fn does_not_flag_when_trailing_newline_present() {
        assert!(run("SELECT 1\nFROM t\n").is_empty());
    }

    #[test]
    fn flags_single_line_without_newline() {
        let sql = "SELECT 1";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_012);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 1\n");
    }

    #[test]
    fn flags_multiple_trailing_newlines() {
        let sql = "SELECT 1\nFROM t\n\n";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_012);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 1\nFROM t\n");
    }

    #[test]
    fn flags_trailing_spaces_after_newline() {
        let sql = "SELECT 1\nFROM t\n  ";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_012);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 1\nFROM t\n");
    }
}
