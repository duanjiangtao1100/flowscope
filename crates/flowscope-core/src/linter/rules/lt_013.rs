//! LINT_LT_013: Layout start of file.
//!
//! SQLFluff LT13 parity (current scope): avoid leading blank lines.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct LayoutStartOfFile;

impl LintRule for LayoutStartOfFile {
    fn code(&self) -> &'static str {
        issue_codes::LINT_LT_013
    }

    fn name(&self) -> &'static str {
        "Layout start of file"
    }

    fn description(&self) -> &'static str {
        "Files must not begin with newlines or whitespace."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        if ctx.statement_index > 0 || !has_leading_blank_lines_for_context(ctx) {
            Vec::new()
        } else {
            let Some(trim_end) = leading_blank_line_trim_end(ctx.sql) else {
                return Vec::new();
            };
            let span = Span::new(0, trim_end);
            vec![Issue::info(
                issue_codes::LINT_LT_013,
                "Avoid leading blank lines at the start of SQL file.",
            )
            .with_statement(ctx.statement_index)
            .with_span(span)
            .with_autofix_edits(
                IssueAutofixApplicability::Safe,
                vec![IssuePatchEdit::new(span, "")],
            )]
        }
    }
}

fn leading_blank_line_trim_end(sql: &str) -> Option<usize> {
    let first_non_ws = sql
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(idx, _)| idx)
        .unwrap_or(sql.len());
    let leading = &sql[..first_non_ws];
    let last_newline = leading.rfind('\n')?;
    let trim_end = last_newline + 1;
    if trim_end == 0 {
        None
    } else {
        Some(trim_end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = LayoutStartOfFile;
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
        for edit in edits.iter().rev() {
            out.replace_range(edit.span.start..edit.span.end, &edit.replacement);
        }
        Some(out)
    }

    #[test]
    fn flags_leading_blank_lines() {
        let issues = run("\n\nSELECT 1");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_013);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix("\n\nSELECT 1", &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 1");
    }

    #[test]
    fn does_not_flag_clean_start() {
        assert!(run("SELECT 1").is_empty());
    }

    #[test]
    fn does_not_flag_leading_comment() {
        assert!(run("-- comment\nSELECT 1").is_empty());
    }

    #[test]
    fn flags_blank_line_before_comment() {
        let sql = "  \n-- comment\nSELECT 1";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_013);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert!(
            fixed.starts_with("-- comment"),
            "comment should remain after LT013 autofix: {fixed}"
        );
    }
}
fn has_leading_blank_lines_for_context(ctx: &LintContext) -> bool {
    let from_document_tokens = ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            None
        } else {
            Some(has_leading_blank_lines_in_tokens(tokens))
        }
    });

    if let Some(has_violation) = from_document_tokens {
        return has_violation;
    }

    has_leading_blank_lines(ctx.sql, ctx.dialect())
}

fn has_leading_blank_lines(sql: &str, dialect: Dialect) -> bool {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let Ok(tokens) = tokenizer.tokenize() else {
        return false;
    };

    for token in tokens {
        match token {
            Token::Whitespace(Whitespace::Space | Whitespace::Tab) => continue,
            Token::Whitespace(Whitespace::Newline) => return true,
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => return false,
            _ => return false,
        }
    }

    false
}

fn has_leading_blank_lines_in_tokens(tokens: &[TokenWithSpan]) -> bool {
    for token in tokens {
        match &token.token {
            Token::Whitespace(Whitespace::Space | Whitespace::Tab) => continue,
            Token::Whitespace(Whitespace::Newline) => return true,
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => return false,
            _ => return false,
        }
    }

    false
}
