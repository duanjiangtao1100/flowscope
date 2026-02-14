//! LINT_LT_008: Layout CTE newline.
//!
//! SQLFluff LT08 parity (current scope): require a blank line between CTE body
//! closing parenthesis and following query/CTE text.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct LayoutCteNewline;

impl LintRule for LayoutCteNewline {
    fn code(&self) -> &'static str {
        issue_codes::LINT_LT_008
    }

    fn name(&self) -> &'static str {
        "Layout CTE newline"
    }

    fn description(&self) -> &'static str {
        "Blank line expected but not found after CTE closing bracket."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        lt08_violation_spans(statement, ctx)
            .into_iter()
            .map(|((start, end), fix_span)| {
                let mut issue = Issue::info(
                    issue_codes::LINT_LT_008,
                    "Blank line expected but not found after CTE closing bracket.",
                )
                .with_statement(ctx.statement_index)
                .with_span(ctx.span_from_statement_offset(start, end));
                if let Some((fix_start, fix_end)) = fix_span {
                    issue = issue.with_autofix_edits(
                        IssueAutofixApplicability::Safe,
                        vec![IssuePatchEdit::new(
                            ctx.span_from_statement_offset(fix_start, fix_end),
                            "\n\n",
                        )],
                    );
                }
                issue
            })
            .collect()
    }
}

#[derive(Clone)]
struct LocatedToken {
    token: Token,
    start: usize,
    end: usize,
}

type Lt08Span = (usize, usize);
type Lt08AutofixSpan = (usize, usize);
type Lt08Violation = (Lt08Span, Option<Lt08AutofixSpan>);

fn lt08_violation_spans(statement: &Statement, ctx: &LintContext) -> Vec<Lt08Violation> {
    let Statement::Query(query) = statement else {
        return Vec::new();
    };
    let Some(with_clause) = &query.with else {
        return Vec::new();
    };

    let Some(tokens) = tokenize_with_offsets_for_context(ctx) else {
        return Vec::new();
    };

    let statement_start = ctx.statement_range.start;
    let mut spans = Vec::new();

    for cte in &with_clause.cte_tables {
        let Some(close_abs) = token_start_offset(ctx.sql, &cte.closing_paren_token.0) else {
            continue;
        };

        if close_abs < ctx.statement_range.start || close_abs >= ctx.statement_range.end {
            continue;
        }

        let (blank_lines, next_code_span) =
            suffix_summary_after_offset(ctx.sql, &tokens, close_abs + 1, ctx.statement_range.end);

        if blank_lines == 0 {
            if let Some((next_start, next_end)) = next_code_span {
                let mut autofix_span = None;
                let gap_start = close_abs + 1;
                if gap_start < next_start {
                    let gap = &ctx.sql[gap_start..next_start];
                    let next_token = &ctx.sql[next_start..next_end];
                    if gap.chars().all(char::is_whitespace)
                        && !gap.contains('\n')
                        && !gap.contains('\r')
                        && next_token.eq_ignore_ascii_case("SELECT")
                    {
                        autofix_span =
                            Some((gap_start - statement_start, next_start - statement_start));
                    }
                }

                spans.push((
                    (next_start - statement_start, next_end - statement_start),
                    autofix_span,
                ));
            }
        }
    }

    spans
}

fn tokenize_with_offsets(sql: &str, dialect: Dialect) -> Option<Vec<LocatedToken>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let tokens = tokenizer.tokenize_with_location().ok()?;

    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let Some(start) = line_col_to_offset(
            sql,
            token.span.start.line as usize,
            token.span.start.column as usize,
        ) else {
            continue;
        };
        let Some(end) = line_col_to_offset(
            sql,
            token.span.end.line as usize,
            token.span.end.column as usize,
        ) else {
            continue;
        };

        out.push(LocatedToken {
            token: token.token,
            start,
            end,
        });
    }

    Some(out)
}

fn tokenize_with_offsets_for_context(ctx: &LintContext) -> Option<Vec<LocatedToken>> {
    let tokens = ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        Some(
            tokens
                .iter()
                .filter_map(|token| {
                    token_with_span_offsets(ctx.sql, token).map(|(start, end)| LocatedToken {
                        token: token.token.clone(),
                        start,
                        end,
                    })
                })
                .collect::<Vec<_>>(),
        )
    });

    if let Some(tokens) = tokens {
        return Some(tokens);
    }

    tokenize_with_offsets(ctx.sql, ctx.dialect())
}

fn token_start_offset(sql: &str, token: &TokenWithSpan) -> Option<usize> {
    line_col_to_offset(
        sql,
        token.span.start.line as usize,
        token.span.start.column as usize,
    )
}

fn suffix_summary_after_offset(
    sql: &str,
    tokens: &[LocatedToken],
    start_offset: usize,
    statement_end: usize,
) -> (usize, Option<(usize, usize)>) {
    let mut blank_lines = 0usize;
    let mut line_blank = false;

    for token in tokens {
        if token.start < start_offset {
            continue;
        }
        if token.start >= statement_end {
            break;
        }

        match &token.token {
            Token::Comma => {
                line_blank = false;
            }
            trivia if is_trivia_token(trivia) => {
                consume_text_for_blank_lines(
                    &sql[token.start..token.end],
                    &mut blank_lines,
                    &mut line_blank,
                );
            }
            _ => return (blank_lines, Some((token.start, token.end))),
        }
    }

    (blank_lines, None)
}

fn consume_text_for_blank_lines(text: &str, blank_lines: &mut usize, line_blank: &mut bool) {
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\n' => {
                if *line_blank {
                    *blank_lines += 1;
                }
                *line_blank = true;
            }
            '\r' => {
                if matches!(chars.peek(), Some('\n')) {
                    let _ = chars.next();
                }
                if *line_blank {
                    *blank_lines += 1;
                }
                *line_blank = true;
            }
            c if c.is_whitespace() => {}
            _ => *line_blank = false,
        }
    }
}

fn is_trivia_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
            | Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = LayoutCteNewline;
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
    fn flags_missing_blank_line_after_cte() {
        let inline_sql = "WITH cte AS (SELECT 1) SELECT * FROM cte";
        let inline_issues = run(inline_sql);
        assert!(!inline_issues.is_empty());
        let autofix = inline_issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(inline_sql, &inline_issues[0]).expect("apply autofix");
        assert_eq!(fixed, "WITH cte AS (SELECT 1)\n\nSELECT * FROM cte");

        let newline_sql = "WITH cte AS (SELECT 1)\nSELECT * FROM cte";
        let newline_issues = run(newline_sql);
        assert!(!newline_issues.is_empty());
        assert!(
            newline_issues[0].autofix.is_none(),
            "single-newline LT008 violation remains report-only"
        );
    }

    #[test]
    fn does_not_flag_with_blank_line_after_cte() {
        assert!(run("WITH cte AS (SELECT 1)\n\nSELECT * FROM cte").is_empty());
    }

    #[test]
    fn flags_each_missing_separator_between_multiple_ctes() {
        let issues = run("WITH a AS (SELECT 1),
-- comment between CTEs
b AS (SELECT 2)
SELECT * FROM b");
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.code == issue_codes::LINT_LT_008)
                .count(),
            2,
        );
    }

    #[test]
    fn comment_only_line_is_not_a_blank_line_separator() {
        assert!(!run("WITH cte AS (SELECT 1)\n-- separator\nSELECT * FROM cte").is_empty());
    }
}
