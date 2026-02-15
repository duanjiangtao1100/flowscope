//! LINT_ST_004: Flattenable nested CASE in ELSE.
//!
//! SQLFluff ST04 parity: flag `CASE ... ELSE CASE ... END END` patterns where
//! the nested ELSE-case can be flattened into the outer CASE.

use crate::linter::rule::{LintContext, LintRule};
use crate::linter::visit;
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{Expr, Spanned, Statement};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct FlattenableNestedCase;

impl LintRule for FlattenableNestedCase {
    fn code(&self) -> &'static str {
        issue_codes::LINT_ST_004
    }

    fn name(&self) -> &'static str {
        "Flattenable nested CASE"
    }

    fn description(&self) -> &'static str {
        "Nested 'CASE' statement in 'ELSE' clause could be flattened."
    }

    fn check(&self, stmt: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut issues = Vec::new();

        visit::visit_expressions(stmt, &mut |expr| {
            if !is_flattenable_nested_else_case(expr) {
                return;
            }

            let mut issue = Issue::warning(
                issue_codes::LINT_ST_004,
                "Nested CASE in ELSE clause can be flattened.",
            )
            .with_statement(ctx.statement_index);

            if let Some((span, edits)) = build_flatten_autofix(ctx, expr) {
                issue = issue
                    .with_span(span)
                    .with_autofix_edits(IssueAutofixApplicability::Unsafe, edits);
            }

            issues.push(issue);
        });

        issues
    }
}

fn is_flattenable_nested_else_case(expr: &Expr) -> bool {
    let Expr::Case {
        operand: outer_operand,
        conditions: outer_conditions,
        else_result: Some(outer_else),
        ..
    } = expr
    else {
        return false;
    };

    // SQLFluff ST04 only applies when there is at least one WHEN in the outer CASE.
    if outer_conditions.is_empty() {
        return false;
    }

    let Some((inner_operand, _inner_conditions, _inner_else)) = case_parts(outer_else) else {
        return false;
    };

    case_operands_match(outer_operand.as_deref(), inner_operand)
}

fn case_parts(
    case_expr: &Expr,
) -> Option<(Option<&Expr>, &[sqlparser::ast::CaseWhen], Option<&Expr>)> {
    match case_expr {
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => Some((
            operand.as_deref(),
            conditions.as_slice(),
            else_result.as_deref(),
        )),
        Expr::Nested(inner) => case_parts(inner),
        _ => None,
    }
}

fn case_operands_match(outer: Option<&Expr>, inner: Option<&Expr>) -> bool {
    match (outer, inner) {
        (None, None) => true,
        (Some(left), Some(right)) => exprs_equal(left, right),
        _ => false,
    }
}

fn exprs_equal(left: &Expr, right: &Expr) -> bool {
    format!("{left}") == format!("{right}")
}

// ---------------------------------------------------------------------------
// Autofix: flatten nested CASE in ELSE clause
// ---------------------------------------------------------------------------

/// Build autofix edits that flatten a nested CASE in ELSE into the outer CASE.
///
/// The transformation removes the ELSE...CASE...END wrapper and promotes the
/// inner CASE's WHEN/ELSE clauses to the outer CASE, preserving comments.
fn build_flatten_autofix(
    ctx: &LintContext,
    outer_expr: &Expr,
) -> Option<(Span, Vec<IssuePatchEdit>)> {
    let Expr::Case {
        else_result: Some(outer_else),
        ..
    } = outer_expr
    else {
        return None;
    };

    let inner_case = unwrap_nested(outer_else);
    let Expr::Case { .. } = inner_case else {
        return None;
    };

    let sql = ctx.statement_sql();

    // Get the outer CASE span in statement coordinates.
    let (outer_start, outer_end) = expr_statement_offsets(ctx, outer_expr)?;
    let outer_span = ctx.span_from_statement_offset(outer_start, outer_end);

    // Tokenize the CASE expression region to find key positions.
    let tokens = tokenize_with_spans(sql, ctx.dialect())?;
    let positioned: Vec<PositionedToken> = tokens
        .iter()
        .filter_map(|token| {
            let (start, end) = token_with_span_offsets(sql, token)?;
            Some(PositionedToken {
                token: token.token.clone(),
                start,
                end,
            })
        })
        .filter(|token| token.start >= outer_start && token.end <= outer_end)
        .collect();

    // Find the ELSE keyword that begins the nested CASE, and the inner CASE/END tokens.
    let flatten_info = find_flatten_positions(&positioned, outer_start)?;

    // The flattened output replaces:
    //   `ELSE [comments-before-case] CASE [operand] [body] END [comments-after-inner-end]`
    // with:
    //   `[comments-between-else-and-case-body] [inner-body] [comments-after-inner-end]`
    //
    // Then also remove the outer's trailing END (replaced by inner's END position).
    let else_start = flatten_info.else_start;
    let inner_case_body_start = flatten_info.inner_body_start;
    let inner_end_start = flatten_info.inner_end_start;
    let inner_end_end = flatten_info.inner_end_end;
    let outer_end_start = flatten_info.outer_end_start;

    // Collect comments between ELSE and inner CASE body.
    let comments_before_body =
        collect_comments_in_range(&positioned, else_start, inner_case_body_start);

    // Collect comments between inner END and outer END.
    let comments_after_inner_end =
        collect_comments_in_range(&positioned, inner_end_end, outer_end_start);

    // Get the inner body text (WHEN/ELSE clauses) starting from the line
    // containing the first WHEN/ELSE keyword.
    let inner_body_line_start = line_start_offset(sql, inner_case_body_start);
    let inner_end_line_start = line_start_offset(sql, inner_end_start);
    let inner_body_full_lines = sql.get(inner_body_line_start..inner_end_line_start)?;

    // Determine indentation levels.
    let outer_indent = find_indent_of_else(sql, else_start);
    let inner_body_indent = find_line_prefix(sql, inner_case_body_start);

    // Build the replacement text.
    let mut replacement = String::new();

    // Add collected comments from between ELSE and inner CASE body.
    for comment in &comments_before_body {
        replacement.push_str(&outer_indent);
        replacement.push_str(comment.trim());
        replacement.push('\n');
    }

    // Add inner body lines, re-indented to match outer CASE indentation.
    let inner_body_trimmed = inner_body_full_lines.trim_end();
    if !inner_body_trimmed.is_empty() {
        for line in inner_body_trimmed.lines() {
            let stripped = strip_indent(line, &inner_body_indent);
            replacement.push_str(&outer_indent);
            replacement.push_str(&stripped);
            replacement.push('\n');
        }
    }

    // Add comments from after inner END.
    for comment in &comments_after_inner_end {
        replacement.push_str(&outer_indent);
        replacement.push_str(comment.trim());
        replacement.push('\n');
    }

    // Trim trailing newline from replacement.
    while replacement.ends_with('\n') {
        replacement.pop();
    }

    // Build a single edit: replace from the start of the ELSE line to the outer END.
    // We start from the line start (after the preceding newline) so that the
    // replacement's own indentation replaces the original ELSE indentation.
    let replace_start = line_start_offset(sql, else_start);
    let replace_end = outer_end;

    // Rebuild the END part: use original outer END formatting (whitespace before END).
    let end_prefix = find_line_prefix(sql, outer_end_start);

    replacement.push('\n');
    replacement.push_str(&end_prefix);
    replacement.push_str("END");

    // Include anything after the outer END keyword (like " AS sound").
    let after_outer_end = outer_end_start + "END".len();
    if after_outer_end < outer_end {
        replacement.push_str(sql.get(after_outer_end..outer_end)?);
    }

    let edit_span = ctx.span_from_statement_offset(replace_start, replace_end);

    Some((
        outer_span,
        vec![IssuePatchEdit::new(edit_span, replacement)],
    ))
}

#[derive(Debug)]
struct FlattenPositions {
    /// Byte offset of the outer ELSE keyword that contains the nested CASE.
    else_start: usize,
    /// Byte offset where the inner CASE body starts (first WHEN or ELSE after CASE keyword).
    inner_body_start: usize,
    /// Byte offset of the inner END keyword.
    inner_end_start: usize,
    /// Byte offset after the inner END keyword.
    inner_end_end: usize,
    /// Byte offset of the outer END keyword.
    outer_end_start: usize,
}

fn find_flatten_positions(
    tokens: &[PositionedToken],
    _outer_start: usize,
) -> Option<FlattenPositions> {
    let significant: Vec<(usize, &PositionedToken)> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| !is_trivia(&t.token))
        .collect();

    if significant.is_empty() {
        return None;
    }

    // Track CASE/END nesting depth.
    let mut depth = 0usize;
    let mut outer_case_idx = None;
    for (sig_idx, (_tok_idx, token)) in significant.iter().enumerate() {
        if token_word_equals(&token.token, "CASE") {
            if depth == 0 {
                outer_case_idx = Some(sig_idx);
            }
            depth += 1;
        } else if token_word_equals(&token.token, "END") {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                // This is the outer END.
                // Find the ELSE at depth 1 that precedes the inner CASE.
                let else_info =
                    find_else_with_nested_case(&significant, outer_case_idx?, sig_idx, tokens)?;
                return Some(else_info);
            }
        }
    }

    None
}

fn find_else_with_nested_case(
    significant: &[(usize, &PositionedToken)],
    outer_case_sig_idx: usize,
    outer_end_sig_idx: usize,
    _tokens: &[PositionedToken],
) -> Option<FlattenPositions> {
    // Walk from the outer CASE to outer END tracking depth.
    let mut depth = 0usize;

    for sig_idx in outer_case_sig_idx..=outer_end_sig_idx {
        let (_, token) = &significant[sig_idx];

        if token_word_equals(&token.token, "CASE") {
            depth += 1;
        }

        if token_word_equals(&token.token, "ELSE") && depth == 1 {
            // Check if the next significant token after ELSE is CASE.
            let next_sig = sig_idx + 1;
            if next_sig < significant.len() {
                let (_, next_token) = &significant[next_sig];
                if token_word_equals(&next_token.token, "CASE") {
                    // Found ELSE followed by CASE.
                    let else_start = token.start;

                    // Find where the inner CASE body starts (after CASE keyword and optional operand).
                    let inner_body_start =
                        find_inner_body_start(significant, next_sig, outer_end_sig_idx)?;

                    // Find the inner END (at depth 2 -> depth 1).
                    let mut inner_depth = 0usize;
                    let mut inner_end_start = None;
                    let mut inner_end_end = None;
                    for (_, inner_token) in
                        significant.iter().take(outer_end_sig_idx).skip(next_sig)
                    {
                        if token_word_equals(&inner_token.token, "CASE") {
                            inner_depth += 1;
                        } else if token_word_equals(&inner_token.token, "END") {
                            inner_depth = inner_depth.saturating_sub(1);
                            if inner_depth == 0 {
                                inner_end_start = Some(inner_token.start);
                                inner_end_end = Some(inner_token.end);
                                break;
                            }
                        }
                    }

                    let outer_end_start = significant[outer_end_sig_idx].1.start;

                    return Some(FlattenPositions {
                        else_start,
                        inner_body_start,
                        inner_end_start: inner_end_start?,
                        inner_end_end: inner_end_end?,
                        outer_end_start,
                    });
                }
            }
        }

        if token_word_equals(&token.token, "END") {
            depth = depth.saturating_sub(1);
        }
    }

    None
}

fn find_inner_body_start(
    significant: &[(usize, &PositionedToken)],
    inner_case_sig_idx: usize,
    outer_end_sig_idx: usize,
) -> Option<usize> {
    // After CASE, skip optional operand until we find WHEN or ELSE.
    let mut depth = 0usize;
    for (_, token) in significant
        .iter()
        .take(outer_end_sig_idx)
        .skip(inner_case_sig_idx)
    {
        if token_word_equals(&token.token, "CASE") {
            depth += 1;
        } else if token_word_equals(&token.token, "END") {
            depth = depth.saturating_sub(1);
        }

        if depth == 1
            && (token_word_equals(&token.token, "WHEN") || token_word_equals(&token.token, "ELSE"))
        {
            return Some(token.start);
        }
    }
    None
}

fn collect_comments_in_range(tokens: &[PositionedToken], start: usize, end: usize) -> Vec<String> {
    tokens
        .iter()
        .filter(|t| t.start >= start && t.end <= end && is_comment(&t.token))
        .map(|t| comment_text(&t.token))
        .collect()
}

fn comment_text(token: &Token) -> String {
    match token {
        Token::Whitespace(Whitespace::SingleLineComment { comment, prefix }) => {
            format!("{prefix}{comment}")
        }
        Token::Whitespace(Whitespace::MultiLineComment(comment)) => {
            format!("/*{comment}*/")
        }
        _ => String::new(),
    }
}

fn line_start_offset(sql: &str, offset: usize) -> usize {
    let before = &sql[..offset];
    match before.rfind('\n') {
        Some(nl_pos) => nl_pos + 1,
        None => 0,
    }
}

fn find_indent_of_else(sql: &str, else_offset: usize) -> String {
    find_line_prefix(sql, else_offset)
}

fn find_line_prefix(sql: &str, offset: usize) -> String {
    let before = &sql[..offset];
    if let Some(nl_pos) = before.rfind('\n') {
        let line_start = nl_pos + 1;
        let prefix = &before[line_start..];
        let indent: String = prefix.chars().take_while(|c| c.is_whitespace()).collect();
        indent
    } else {
        // First line — no leading whitespace assumed.
        let indent: String = before.chars().take_while(|c| c.is_whitespace()).collect();
        indent
    }
}

fn strip_indent(line: &str, indent: &str) -> String {
    if let Some(stripped) = line.strip_prefix(indent) {
        stripped.to_string()
    } else {
        line.trim_start().to_string()
    }
}

fn unwrap_nested(expr: &Expr) -> &Expr {
    match expr {
        Expr::Nested(inner) => unwrap_nested(inner),
        _ => expr,
    }
}

// ---------------------------------------------------------------------------
// Span and offset utilities
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PositionedToken {
    token: Token,
    start: usize,
    end: usize,
}

fn expr_statement_offsets(ctx: &LintContext, expr: &Expr) -> Option<(usize, usize)> {
    if let Some((start, end)) = expr_span_offsets(ctx.statement_sql(), expr) {
        return Some((start, end));
    }

    let (start, end) = expr_span_offsets(ctx.sql, expr)?;
    if start < ctx.statement_range.start || end > ctx.statement_range.end {
        return None;
    }

    Some((
        start - ctx.statement_range.start,
        end - ctx.statement_range.start,
    ))
}

fn expr_span_offsets(sql: &str, expr: &Expr) -> Option<(usize, usize)> {
    let span = expr.span();
    if span.start.line == 0 || span.start.column == 0 || span.end.line == 0 || span.end.column == 0
    {
        return None;
    }

    let start = line_col_to_offset(sql, span.start.line as usize, span.start.column as usize)?;
    let end = line_col_to_offset(sql, span.end.line as usize, span.end.column as usize)?;
    (end >= start).then_some((start, end))
}

fn tokenize_with_spans(sql: &str, dialect: crate::types::Dialect) -> Option<Vec<TokenWithSpan>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    tokenizer.tokenize_with_location().ok()
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
    let mut line_start = 0usize;

    for (idx, ch) in sql.char_indices() {
        if current_line == line {
            break;
        }
        if ch == '\n' {
            current_line += 1;
            line_start = idx + ch.len_utf8();
        }
    }
    if current_line != line {
        return None;
    }

    let mut current_column = 1usize;
    for (rel_idx, ch) in sql[line_start..].char_indices() {
        if current_column == column {
            return Some(line_start + rel_idx);
        }
        if ch == '\n' {
            return None;
        }
        current_column += 1;
    }

    if current_column == column {
        return Some(sql.len());
    }

    None
}

fn token_word_equals(token: &Token, expected_upper: &str) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case(expected_upper))
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

fn is_comment(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssuePatchEdit;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = FlattenableNestedCase;
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

    fn apply_edits(sql: &str, edits: &[IssuePatchEdit]) -> String {
        let mut output = sql.to_string();
        let mut ordered = edits.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|edit| edit.span.start);

        for edit in ordered.into_iter().rev() {
            output.replace_range(edit.span.start..edit.span.end, &edit.replacement);
        }

        output
    }

    // --- Pass cases from SQLFluff ST04 fixture ---

    #[test]
    fn passes_nested_case_under_when_clause() {
        let sql = "SELECT CASE WHEN species = 'Rat' THEN CASE WHEN colour = 'Black' THEN 'Growl' WHEN colour = 'Grey' THEN 'Squeak' END END AS sound FROM mytable";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn passes_nested_case_inside_larger_else_expression() {
        let sql = "SELECT CASE WHEN flag = 1 THEN TRUE ELSE score > 10 + CASE WHEN kind = 'b' THEN 8 WHEN kind = 'c' THEN 9 END END AS test FROM t";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn passes_when_outer_and_inner_case_operands_differ() {
        let sql = "SELECT CASE WHEN day_of_month IN (11, 12, 13) THEN 'TH' ELSE CASE MOD(day_of_month, 10) WHEN 1 THEN 'ST' WHEN 2 THEN 'ND' WHEN 3 THEN 'RD' ELSE 'TH' END END AS ordinal_suffix FROM calendar";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    #[test]
    fn passes_different_case_expressions2() {
        let sql = "SELECT CASE DayOfMonth WHEN 11 THEN 'TH' WHEN 12 THEN 'TH' WHEN 13 THEN 'TH' ELSE CASE MOD(DayOfMonth, 10) WHEN 1 THEN 'ST' WHEN 2 THEN 'ND' WHEN 3 THEN 'RD' ELSE 'TH' END END AS OrdinalSuffix FROM Calendar";
        let issues = run(sql);
        assert!(issues.is_empty());
    }

    // --- Fail + detection cases ---

    #[test]
    fn flags_simple_flattenable_else_case() {
        let sql = "SELECT CASE WHEN species = 'Rat' THEN 'Squeak' ELSE CASE WHEN species = 'Dog' THEN 'Woof' END END AS sound FROM mytable";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_004);
    }

    #[test]
    fn flags_nested_else_case_with_multiple_when_clauses() {
        let sql = "SELECT CASE WHEN species = 'Rat' THEN 'Squeak' ELSE CASE WHEN species = 'Dog' THEN 'Woof' WHEN species = 'Mouse' THEN 'Squeak' END END AS sound FROM mytable";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn flags_when_outer_and_inner_simple_case_operands_match() {
        let sql = "SELECT CASE x WHEN 0 THEN 'zero' WHEN 5 THEN 'five' ELSE CASE x WHEN 10 THEN 'ten' WHEN 20 THEN 'twenty' ELSE 'other' END END FROM tab_a";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
    }

    // --- Autofix tests matching SQLFluff fixture fix_str ---

    #[test]
    fn autofix_simple_flatten() {
        let sql = "\
SELECT
    c1,
    CASE
        WHEN species = 'Rat' THEN 'Squeak'
        ELSE
            CASE
                WHEN species = 'Dog' THEN 'Woof'
            END
    END AS sound
FROM mytable";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);

        let expected = "\
SELECT
    c1,
    CASE
        WHEN species = 'Rat' THEN 'Squeak'
        WHEN species = 'Dog' THEN 'Woof'
    END AS sound
FROM mytable";
        assert_eq!(fixed, expected);
    }

    #[test]
    fn autofix_flatten_multiple_whens() {
        let sql = "\
SELECT
    c1,
    CASE
        WHEN species = 'Rat' THEN 'Squeak'
        ELSE
            CASE
                WHEN species = 'Dog' THEN 'Woof'
                WHEN species = 'Mouse' THEN 'Squeak'
            END
    END AS sound
FROM mytable";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);

        let expected = "\
SELECT
    c1,
    CASE
        WHEN species = 'Rat' THEN 'Squeak'
        WHEN species = 'Dog' THEN 'Woof'
        WHEN species = 'Mouse' THEN 'Squeak'
    END AS sound
FROM mytable";
        assert_eq!(fixed, expected);
    }

    #[test]
    fn autofix_flatten_with_else() {
        let sql = "\
SELECT
    c1,
    CASE
        WHEN species = 'Rat' THEN 'Squeak'
        ELSE
            CASE
                WHEN species = 'Dog' THEN 'Woof'
                WHEN species = 'Mouse' THEN 'Squeak'
                ELSE \"Whaa\"
            END
    END AS sound
FROM mytable";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);

        let expected = "\
SELECT
    c1,
    CASE
        WHEN species = 'Rat' THEN 'Squeak'
        WHEN species = 'Dog' THEN 'Woof'
        WHEN species = 'Mouse' THEN 'Squeak'
        ELSE \"Whaa\"
    END AS sound
FROM mytable";
        assert_eq!(fixed, expected);
    }

    #[test]
    fn autofix_flatten_same_simple_case_operand() {
        let sql = "\
SELECT
    CASE x
        WHEN 0 THEN 'zero'
        WHEN 5 THEN 'five'
        ELSE
            CASE x
                WHEN 10 THEN 'ten'
                WHEN 20 THEN 'twenty'
                ELSE 'other'
            END
    END
FROM tab_a;";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("expected autofix");
        let fixed = apply_edits(sql, &autofix.edits);

        let expected = "\
SELECT
    CASE x
        WHEN 0 THEN 'zero'
        WHEN 5 THEN 'five'
        WHEN 10 THEN 'ten'
        WHEN 20 THEN 'twenty'
        ELSE 'other'
    END
FROM tab_a;";
        assert_eq!(fixed, expected);
    }
}
