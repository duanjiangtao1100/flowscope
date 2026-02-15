//! LINT_LT_001: Layout spacing.
//!
//! SQLFluff LT01 parity: comprehensive spacing checks covering operators,
//! commas, brackets, keywords, literals, trailing whitespace, excessive
//! whitespace, and cast operators.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::Statement;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Location, Span, Token, TokenWithSpan, Tokenizer, Whitespace};

pub struct LayoutSpacing;

impl LintRule for LayoutSpacing {
    fn code(&self) -> &'static str {
        issue_codes::LINT_LT_001
    }

    fn name(&self) -> &'static str {
        "Layout spacing"
    }

    fn description(&self) -> &'static str {
        "Inappropriate Spacing."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        spacing_violations(ctx)
            .into_iter()
            .map(|((start, end), edits)| {
                let mut issue =
                    Issue::info(issue_codes::LINT_LT_001, "Inappropriate spacing found.")
                        .with_statement(ctx.statement_index)
                        .with_span(ctx.span_from_statement_offset(start, end));
                if !edits.is_empty() {
                    let edits = edits
                        .into_iter()
                        .map(|(edit_start, edit_end, replacement)| {
                            IssuePatchEdit::new(
                                ctx.span_from_statement_offset(edit_start, edit_end),
                                replacement.to_string(),
                            )
                        })
                        .collect();
                    issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, edits);
                }
                issue
            })
            .collect()
    }
}

type Lt01Span = (usize, usize);
type Lt01AutofixEdit = (usize, usize, String);
type Lt01Violation = (Lt01Span, Vec<Lt01AutofixEdit>);

fn spacing_violations(ctx: &LintContext) -> Vec<Lt01Violation> {
    let sql = ctx.statement_sql();
    let mut violations = Vec::new();
    let tokens = tokenized_for_context(ctx).or_else(|| tokenized(sql, ctx.dialect()));
    let Some(tokens) = tokens else {
        return violations;
    };

    let dialect = ctx.dialect();

    collect_trailing_whitespace_violations(sql, &mut violations);
    collect_pair_spacing_violations(sql, &tokens, dialect, &mut violations);
    collect_exists_line_paren_violations(sql, &tokens, &mut violations);

    violations.sort_unstable_by_key(|(span, _)| *span);
    violations.dedup_by_key(|(span, _)| *span);

    violations
}

// ---------------------------------------------------------------------------
// Trailing whitespace
// ---------------------------------------------------------------------------

fn collect_trailing_whitespace_violations(sql: &str, violations: &mut Vec<Lt01Violation>) {
    let mut offset = 0;
    for line in sql.split('\n') {
        let trimmed = line.trim_end_matches([' ', '\t']);
        let trailing_start = offset + trimmed.len();
        let trailing_end = offset + line.len();
        if trailing_end > trailing_start {
            let span = (trailing_start, trailing_end);
            let edit = (trailing_start, trailing_end, String::new());
            violations.push((span, vec![edit]));
        }
        offset += line.len() + 1; // +1 for the \n
    }
}

// ---------------------------------------------------------------------------
// Pair-based spacing: walk consecutive non-trivia token pairs
// ---------------------------------------------------------------------------

/// Expected spacing between two adjacent non-trivia tokens.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ExpectedSpacing {
    /// Exactly one space required (or newline acceptable).
    Single,
    /// No space allowed (tokens must be adjacent).
    None,
    /// Do not check this pair (e.g. start/end of statement).
    Skip,
    /// Single space required, and if there's a newline between, replace with single space.
    SingleInline,
    /// Single space required — report violation but do NOT emit autofix edits.
    /// Used for spacing around comparison operators to avoid overlapping with CV001
    /// operator-normalisation patches in the fix planner.
    SingleReportOnly,
}

fn collect_pair_spacing_violations(
    sql: &str,
    tokens: &[TokenWithSpan],
    dialect: Dialect,
    violations: &mut Vec<Lt01Violation>,
) {
    let non_trivia: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| !is_trivia_token(&t.token) && !matches!(t.token, Token::EOF))
        .map(|(i, _)| i)
        .collect();

    for window in non_trivia.windows(2) {
        let left_idx = window[0];
        let right_idx = window[1];
        let left = &tokens[left_idx];
        let right = &tokens[right_idx];

        let Some((_, left_end)) = token_offsets(sql, left) else {
            continue;
        };
        let Some((right_start, _)) = token_offsets(sql, right) else {
            continue;
        };

        if left_end > right_start || right_start > sql.len() || left_end > sql.len() {
            continue;
        }

        let gap = &sql[left_end..right_start];
        let has_newline = gap.contains('\n') || gap.contains('\r');
        let has_comment = has_comment_between(tokens, left_idx, right_idx);

        let expected = expected_spacing(left, right, tokens, left_idx, right_idx, dialect);

        match expected {
            ExpectedSpacing::Skip => continue,
            ExpectedSpacing::None => {
                // Tokens should be adjacent, no whitespace allowed.
                if !gap.is_empty() && !has_newline && !has_comment {
                    let span = (left_end, right_start);
                    let edit = (left_end, right_start, String::new());
                    violations.push((span, vec![edit]));
                }
            }
            ExpectedSpacing::Single => {
                if has_comment {
                    continue;
                }
                if has_newline {
                    // Newline is acceptable as a separator for single-space contexts.
                    // But check if there's excessive inline space on the same line
                    // before or after the newline.
                    continue;
                }
                if gap == " " {
                    // Correct single space.
                    continue;
                }
                // Either missing space (gap is empty) or excessive space (multiple spaces).
                let span = (left_end, right_start);
                let edit = (left_end, right_start, " ".to_string());
                violations.push((span, vec![edit]));
            }
            ExpectedSpacing::SingleInline => {
                if has_comment {
                    continue;
                }
                if gap == " " {
                    continue;
                }
                // Replace whatever gap (including newlines) with single space.
                let span = (left_end, right_start);
                let edit = (left_end, right_start, " ".to_string());
                violations.push((span, vec![edit]));
            }
            ExpectedSpacing::SingleReportOnly => {
                if has_comment || has_newline {
                    continue;
                }
                if gap == " " {
                    continue;
                }
                // Report-only: flag the spacing issue but skip autofix edits to
                // avoid overlapping with CV001 operator patches.
                let span = (left_end, right_start);
                violations.push((span, Vec::new()));
            }
        }
    }
}

/// Determine expected spacing between two adjacent non-trivia tokens.
fn expected_spacing(
    left: &TokenWithSpan,
    right: &TokenWithSpan,
    tokens: &[TokenWithSpan],
    left_idx: usize,
    right_idx: usize,
    dialect: Dialect,
) -> ExpectedSpacing {
    // --- Period (dot) for qualified identifiers: no space around ---
    if matches!(left.token, Token::Period) || matches!(right.token, Token::Period) {
        return ExpectedSpacing::None;
    }

    // --- Cast operator (::) ---
    if matches!(left.token, Token::DoubleColon) || matches!(right.token, Token::DoubleColon) {
        return ExpectedSpacing::None;
    }

    // --- Snowflake colon (semi-structured access): no space around ---
    if dialect == Dialect::Snowflake
        && (matches!(left.token, Token::Colon) || matches!(right.token, Token::Colon))
    {
        // Snowflake a:b:c syntax — no spaces around colon
        return ExpectedSpacing::None;
    }

    // --- Left paren: usually no space before (function calls) ---
    if matches!(right.token, Token::LParen) {
        return expected_spacing_before_lparen(left, tokens, left_idx, dialect);
    }

    // --- Right paren followed by something ---
    if matches!(left.token, Token::RParen) {
        return expected_spacing_after_rparen(right, tokens, right_idx);
    }

    // --- Left bracket: no space before in most contexts ---
    if matches!(right.token, Token::LBracket) {
        // text[] type syntax needs a space, but array access doesn't.
        if is_type_keyword_for_bracket(&left.token) {
            return ExpectedSpacing::Single;
        }
        return ExpectedSpacing::None;
    }

    // --- Right bracket ---
    if matches!(left.token, Token::RBracket) {
        // After ] usually no space before :: or . or [
        if matches!(
            right.token,
            Token::DoubleColon | Token::Period | Token::LBracket
        ) {
            return ExpectedSpacing::None;
        }
        return ExpectedSpacing::Single;
    }

    // --- Comma: no space before, single space after ---
    if matches!(right.token, Token::Comma) {
        return ExpectedSpacing::None;
    }
    if matches!(left.token, Token::Comma) {
        return ExpectedSpacing::Single;
    }

    // --- Semicolon: no space before ---
    if matches!(right.token, Token::SemiColon) {
        return ExpectedSpacing::Skip;
    }
    if matches!(left.token, Token::SemiColon) {
        return ExpectedSpacing::Skip;
    }

    // --- Inside parens: no space after ( or before ) ---
    if matches!(left.token, Token::LParen) {
        return ExpectedSpacing::None;
    }
    if matches!(right.token, Token::RParen) {
        return ExpectedSpacing::None;
    }

    // --- Binary operators: single space on each side ---
    if is_binary_operator(&left.token) || is_binary_operator(&right.token) {
        // Special: unary minus/plus (sign indicators) — skip
        if is_unary_operator_pair(left, right, tokens, left_idx) {
            return ExpectedSpacing::Skip;
        }
        return ExpectedSpacing::Single;
    }

    // --- Comparison operators: report-only to avoid overlapping with CV001 ---
    if is_comparison_operator(&left.token) || is_comparison_operator(&right.token) {
        return ExpectedSpacing::SingleReportOnly;
    }

    // --- JSON operators (arrow, long arrow, etc.) ---
    if is_json_operator(&left.token) || is_json_operator(&right.token) {
        return ExpectedSpacing::Single;
    }

    // --- Star/Mul as wildcard inside COUNT(*) etc. ---
    if matches!(left.token, Token::Mul) || matches!(right.token, Token::Mul) {
        // If inside parens: skip (could be wildcard)
        return ExpectedSpacing::Skip;
    }

    // --- Keywords and identifiers: single space between ---
    if is_word_like(&left.token) && is_word_like(&right.token) {
        return ExpectedSpacing::Single;
    }

    // --- Word followed by literal or vice versa ---
    if (is_word_like(&left.token) && is_literal(&right.token))
        || (is_literal(&left.token) && is_word_like(&right.token))
    {
        return ExpectedSpacing::Single;
    }

    // --- Literal followed by literal ---
    if is_literal(&left.token) && is_literal(&right.token) {
        return ExpectedSpacing::Single;
    }

    // --- Number followed by word or vice versa ---
    if (matches!(left.token, Token::Number(_, _)) && is_word_like(&right.token))
        || (is_word_like(&left.token) && matches!(right.token, Token::Number(_, _)))
    {
        return ExpectedSpacing::Single;
    }

    ExpectedSpacing::Skip
}

// ---------------------------------------------------------------------------
// Token classification helpers
// ---------------------------------------------------------------------------

fn is_binary_operator(token: &Token) -> bool {
    matches!(
        token,
        Token::Plus
            | Token::Minus
            | Token::Div
            | Token::Mod
            | Token::StringConcat
            | Token::Ampersand
            | Token::Pipe
            | Token::Caret
            | Token::ShiftLeft
            | Token::ShiftRight
            | Token::Assignment
    )
}

fn is_comparison_operator(token: &Token) -> bool {
    matches!(
        token,
        Token::Eq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq
            | Token::Spaceship
            | Token::DoubleEq
            | Token::TildeEqual
    )
}

fn is_json_operator(token: &Token) -> bool {
    matches!(
        token,
        Token::Arrow
            | Token::LongArrow
            | Token::HashArrow
            | Token::HashLongArrow
            | Token::AtArrow
            | Token::ArrowAt
    )
}

fn is_word_like(token: &Token) -> bool {
    matches!(token, Token::Word(_) | Token::Placeholder(_))
}

fn is_literal(token: &Token) -> bool {
    matches!(
        token,
        Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::NationalStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::Number(_, _)
    )
}

fn is_type_keyword_for_bracket(token: &Token) -> bool {
    if let Token::Word(w) = token {
        w.quote_style.is_none() && w.value.eq_ignore_ascii_case("text")
    } else {
        false
    }
}

/// Check if a token is a DDL keyword after which the next word is an object name
/// (table, view, index, etc.) — not a function call.
fn is_ddl_object_keyword(token: &Token) -> bool {
    if let Token::Word(w) = token {
        matches!(
            w.keyword,
            Keyword::TABLE
                | Keyword::VIEW
                | Keyword::INDEX
                | Keyword::FUNCTION
                | Keyword::PROCEDURE
                | Keyword::TRIGGER
                | Keyword::SEQUENCE
                | Keyword::TYPE
                | Keyword::SCHEMA
                | Keyword::DATABASE
        )
    } else {
        false
    }
}

/// Check if this pair involves a unary +/- (sign indicator) rather than binary.
fn is_unary_operator_pair(
    left: &TokenWithSpan,
    right: &TokenWithSpan,
    tokens: &[TokenWithSpan],
    left_idx: usize,
) -> bool {
    // Case 1: right token is +/- and left context suggests unary
    if matches!(right.token, Token::Plus | Token::Minus)
        && is_unary_prefix_context(&tokens[left_idx].token)
    {
        return true;
    }
    // Case 2: left token is +/- and the token before it suggests unary
    if matches!(left.token, Token::Plus | Token::Minus) {
        if let Some(prev_idx) = prev_non_trivia_index(tokens, left_idx) {
            if is_unary_prefix_context(&tokens[prev_idx].token) {
                return true;
            }
        } else {
            // No previous token — start of statement, so it's unary
            return true;
        }
    }
    false
}

/// Check if a token is a context where the following +/- is unary.
fn is_unary_prefix_context(token: &Token) -> bool {
    if matches!(
        token,
        Token::Comma
            | Token::LParen
            | Token::Eq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq
    ) {
        return true;
    }
    if let Token::Word(w) = token {
        if matches!(
            w.keyword,
            Keyword::SELECT
                | Keyword::WHERE
                | Keyword::WHEN
                | Keyword::THEN
                | Keyword::ELSE
                | Keyword::AND
                | Keyword::OR
                | Keyword::ON
                | Keyword::SET
                | Keyword::CASE
                | Keyword::BETWEEN
                | Keyword::IN
                | Keyword::VALUES
                | Keyword::INTERVAL
                | Keyword::RETURN
                | Keyword::RETURNS
        ) {
            return true;
        }
    }
    false
}

/// Expected spacing before left-paren.
fn expected_spacing_before_lparen(
    left: &TokenWithSpan,
    tokens: &[TokenWithSpan],
    left_idx: usize,
    _dialect: Dialect,
) -> ExpectedSpacing {
    match &left.token {
        // Function call: no space between function name and (
        Token::Word(w) if w.quote_style.is_none() => {
            // Keywords that should have a space before (
            if is_keyword_requiring_space_before_paren(w.keyword) {
                // AS in CTE: `AS (` should be single-inline (collapse newlines to space)
                // USING, FROM, etc.: single space (newline acceptable)
                if matches!(w.keyword, Keyword::AS) {
                    return ExpectedSpacing::SingleInline;
                }
                return ExpectedSpacing::Single;
            }
            // Check if this word is a table/view name after CREATE TABLE/VIEW —
            // the ( opens a column list, not a function call, so skip.
            if w.keyword == Keyword::NoKeyword {
                if let Some(prev_idx) = prev_non_trivia_index(tokens, left_idx) {
                    if is_ddl_object_keyword(&tokens[prev_idx].token) {
                        return ExpectedSpacing::Skip;
                    }
                }
            }
            // Regular function call or type name: no space
            ExpectedSpacing::None
        }
        // After closing paren/bracket: single space (subquery, etc.)
        Token::RParen | Token::RBracket => ExpectedSpacing::Single,
        // After literal: single space
        _ if is_literal(&left.token) => ExpectedSpacing::Single,
        // After number: no space (could be type precision like numeric(5,2))
        Token::Number(_, _) => ExpectedSpacing::None,
        // After comma: single space
        Token::Comma => ExpectedSpacing::Single,
        // After operator: skip
        _ if is_binary_operator(&left.token) || is_comparison_operator(&left.token) => {
            ExpectedSpacing::Skip
        }
        _ => ExpectedSpacing::Skip,
    }
}

/// Keywords that should have a space before `(`.
fn is_keyword_requiring_space_before_paren(keyword: Keyword) -> bool {
    matches!(
        keyword,
        Keyword::AS
            | Keyword::USING
            | Keyword::FROM
            | Keyword::JOIN
            | Keyword::ON
            | Keyword::WHERE
            | Keyword::IN
            | Keyword::EXISTS
            | Keyword::BETWEEN
            | Keyword::WHEN
            | Keyword::THEN
            | Keyword::ELSE
            | Keyword::AND
            | Keyword::OR
            | Keyword::NOT
            | Keyword::HAVING
            | Keyword::OVER
            | Keyword::PARTITION
            | Keyword::ORDER
            | Keyword::GROUP
            | Keyword::LIMIT
            | Keyword::UNION
            | Keyword::INTERSECT
            | Keyword::EXCEPT
            | Keyword::RECURSIVE
            | Keyword::WITH
            | Keyword::SELECT
            | Keyword::INTO
            | Keyword::TABLE
            | Keyword::VALUES
            | Keyword::SET
            | Keyword::RETURNS
    )
}

/// Expected spacing after right-paren.
fn expected_spacing_after_rparen(
    right: &TokenWithSpan,
    _tokens: &[TokenWithSpan],
    _right_idx: usize,
) -> ExpectedSpacing {
    match &right.token {
        // ) followed by . or :: or [ — no space
        Token::Period | Token::DoubleColon | Token::LBracket => ExpectedSpacing::None,
        // ) followed by , — no space before comma
        Token::Comma => ExpectedSpacing::None,
        // ) followed by ; — no space
        Token::SemiColon => ExpectedSpacing::Skip,
        // ) followed by ) — no space
        Token::RParen => ExpectedSpacing::None,
        // ) followed by ( — single space
        Token::LParen => ExpectedSpacing::Single,
        // ) followed by keyword or identifier — single space
        _ => ExpectedSpacing::Single,
    }
}

fn has_comment_between(tokens: &[TokenWithSpan], left: usize, right: usize) -> bool {
    tokens[left + 1..right].iter().any(|t| {
        matches!(
            t.token,
            Token::Whitespace(Whitespace::SingleLineComment { .. })
                | Token::Whitespace(Whitespace::MultiLineComment(_))
        )
    })
}

// ---------------------------------------------------------------------------
// EXISTS-on-new-line special check (report-only, no autofix)
// ---------------------------------------------------------------------------

fn collect_exists_line_paren_violations(
    sql: &str,
    tokens: &[TokenWithSpan],
    violations: &mut Vec<Lt01Violation>,
) {
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        if word.keyword != Keyword::EXISTS {
            continue;
        }

        let Some(next_index) = next_non_trivia_index(tokens, index + 1) else {
            continue;
        };
        if !matches!(tokens[next_index].token, Token::LParen) {
            continue;
        }
        if !has_trivia_between(tokens, index, next_index) {
            continue;
        }

        if previous_line_ends_with_boolean_keyword(tokens, index) {
            continue;
        }

        let Some((exists_start, _)) = token_offsets(sql, token) else {
            continue;
        };
        if !line_prefix_is_whitespace(sql, exists_start) {
            continue;
        }

        if let Some((paren_start, _)) = token_offsets(sql, &tokens[next_index]) {
            violations.push((single_char_span(sql, paren_start), Vec::new()));
        }
    }
}

// ---------------------------------------------------------------------------
// Token utilities
// ---------------------------------------------------------------------------

fn tokenized(sql: &str, dialect: Dialect) -> Option<Vec<TokenWithSpan>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    tokenizer.tokenize_with_location().ok()
}

fn tokenized_for_context(ctx: &LintContext) -> Option<Vec<TokenWithSpan>> {
    let (statement_start_line, statement_start_column) =
        offset_to_line_col(ctx.sql, ctx.statement_range.start)?;

    ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        let mut out = Vec::new();
        for token in tokens {
            let Some((start, end)) = token_with_span_offsets(ctx.sql, token) else {
                continue;
            };
            if start < ctx.statement_range.start || end > ctx.statement_range.end {
                continue;
            }

            let Some(start_loc) = relative_location(
                token.span.start,
                statement_start_line,
                statement_start_column,
            ) else {
                continue;
            };
            let Some(end_loc) =
                relative_location(token.span.end, statement_start_line, statement_start_column)
            else {
                continue;
            };

            out.push(TokenWithSpan::new(
                token.token.clone(),
                Span::new(start_loc, end_loc),
            ));
        }

        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    })
}

fn previous_line_ends_with_boolean_keyword(tokens: &[TokenWithSpan], index: usize) -> bool {
    let Some(prev_index) = prev_non_trivia_index(tokens, index) else {
        return false;
    };
    let Token::Word(prev_word) = &tokens[prev_index].token else {
        return false;
    };
    if !matches!(prev_word.keyword, Keyword::AND | Keyword::OR | Keyword::NOT) {
        return false;
    }

    tokens[prev_index].span.end.line < tokens[index].span.start.line
}

fn line_prefix_is_whitespace(sql: &str, offset: usize) -> bool {
    let line_start = sql[..offset].rfind('\n').map_or(0, |index| index + 1);
    sql[line_start..offset].chars().all(char::is_whitespace)
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

fn single_char_span(sql: &str, start: usize) -> (usize, usize) {
    let end = (start + 1).min(sql.len());
    (start, end)
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

fn prev_non_trivia_index(tokens: &[TokenWithSpan], mut index: usize) -> Option<usize> {
    while index > 0 {
        index -= 1;
        if !is_trivia_token(&tokens[index].token) {
            return Some(index);
        }
    }
    None
}

fn has_trivia_between(tokens: &[TokenWithSpan], left: usize, right: usize) -> bool {
    right > left + 1
        && tokens[left + 1..right]
            .iter()
            .any(|token| is_trivia_token(&token.token))
}

fn is_trivia_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Newline | Whitespace::Tab)
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

fn offset_to_line_col(sql: &str, offset: usize) -> Option<(usize, usize)> {
    if offset > sql.len() {
        return None;
    }
    if offset == sql.len() {
        let line = 1 + sql.as_bytes().iter().filter(|byte| **byte == b'\n').count();
        let column = sql
            .rsplit_once('\n')
            .map_or(sql.chars().count() + 1, |(_, tail)| {
                tail.chars().count() + 1
            });
        return Some((line, column));
    }

    let mut line = 1usize;
    let mut column = 1usize;
    for (index, ch) in sql.char_indices() {
        if index == offset {
            return Some((line, column));
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    Some((line, column))
}

fn relative_location(
    location: Location,
    statement_start_line: usize,
    statement_start_column: usize,
) -> Option<Location> {
    if location.line == 0 || location.column == 0 {
        return None;
    }

    let line = location.line as usize;
    let column = location.column as usize;
    if line < statement_start_line {
        return None;
    }

    let relative_line = line - statement_start_line + 1;
    let relative_column = if line == statement_start_line {
        if column < statement_start_column {
            return None;
        }
        column - statement_start_column + 1
    } else {
        column
    };

    Some(Location::new(relative_line as u64, relative_column as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = LayoutSpacing;
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

    fn apply_all_issue_autofixes(sql: &str, issues: &[Issue]) -> String {
        let mut out = sql.to_string();
        let mut edits = issues
            .iter()
            .filter_map(|issue| issue.autofix.as_ref())
            .flat_map(|autofix| autofix.edits.clone())
            .collect::<Vec<_>>();
        edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
        for edit in edits.into_iter().rev() {
            out.replace_range(edit.span.start..edit.span.end, &edit.replacement);
        }
        out
    }

    // --- Trailing whitespace tests ---

    #[test]
    fn flags_trailing_whitespace() {
        let sql = "SELECT 1     \n";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag trailing whitespace");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT 1\n");
    }

    #[test]
    fn flags_trailing_whitespace_on_initial_blank_line() {
        let sql = " \nSELECT 1     \n";
        let issues = run(sql);
        assert!(!issues.is_empty());
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "\nSELECT 1\n");
    }

    // --- Operator spacing tests ---

    #[test]
    fn flags_compact_operator() {
        let sql = "SELECT 1+2";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag compact 1+2");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT 1 + 2");
    }

    #[test]
    fn flags_compact_operator_expression() {
        let sql = "select\n    field,\n    date(field_1)-date(field_2) as diff\nfrom tbl";
        let issues = run(sql);
        assert!(!issues.is_empty());
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert!(
            fixed.contains("date(field_1) - date(field_2)"),
            "should fix operator spacing: {fixed}"
        );
    }

    #[test]
    fn flags_plus_between_identifier_and_literal() {
        let sql = "SELECT a +'b'+ 'c' FROM tbl";
        let issues = run(sql);
        assert!(
            !issues.is_empty(),
            "should flag operator spacing around string literals"
        );
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT a + 'b' + 'c' FROM tbl");
    }

    #[test]
    fn does_not_flag_simple_spacing() {
        assert!(run("SELECT * FROM t WHERE a = 1").is_empty());
    }

    #[test]
    fn does_not_flag_sign_indicators() {
        let issues = run("SELECT 1, +2, -4");
        // Sign indicators before numbers should not be flagged
        assert!(
            issues.is_empty(),
            "unary signs should not be flagged: {issues:?}"
        );
    }

    #[test]
    fn does_not_flag_newline_operator() {
        assert!(run("SELECT 1\n+ 2").is_empty());
        assert!(run("SELECT 1\n    + 2").is_empty());
    }

    // --- Comma spacing tests ---

    #[test]
    fn flags_space_before_comma() {
        let sql = "SELECT 1 ,4";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag space before comma");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT 1, 4");
    }

    #[test]
    fn flags_no_space_after_comma() {
        let sql = "SELECT 1,4";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag missing space after comma");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT 1, 4");
    }

    #[test]
    fn flags_excessive_space_after_comma() {
        let sql = "SELECT 1,   4";
        let issues = run(sql);
        assert!(
            !issues.is_empty(),
            "should flag excessive space after comma"
        );
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT 1, 4");
    }

    // --- Bracket spacing tests ---

    #[test]
    fn flags_missing_space_before_paren_after_keyword() {
        let sql = "SELECT * FROM(SELECT 1 AS C1)AS T1;";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag FROM( and )AS: {issues:?}");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT * FROM (SELECT 1 AS C1) AS T1;");
    }

    // --- Missing space tests ---

    #[test]
    fn flags_cte_missing_space_after_as() {
        let sql = "WITH a AS(select 1) select * from a";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag AS(");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "WITH a AS (select 1) select * from a");
    }

    #[test]
    fn flags_cte_multiple_spaces_after_as() {
        let sql = "WITH a AS  (select 1) select * from a";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag AS  (");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "WITH a AS (select 1) select * from a");
    }

    #[test]
    fn flags_missing_space_after_using() {
        let sql = "select * from a JOIN b USING(x)";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag USING(");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "select * from a JOIN b USING (x)");
    }

    // --- Excessive whitespace tests ---

    #[test]
    fn flags_excessive_whitespace() {
        let sql = "SELECT     1";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag excessive whitespace");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT 1");
    }

    #[test]
    fn flags_excessive_whitespace_multi() {
        let sql = "select\n    1 + 2     + 3     + 4        -- Comment\nfrom     foo";
        let issues = run(sql);
        assert!(!issues.is_empty());
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(
            fixed,
            "select\n    1 + 2 + 3 + 4        -- Comment\nfrom foo"
        );
    }

    // --- Literal spacing tests ---

    #[test]
    fn flags_literal_operator_spacing() {
        let sql = "SELECT ('foo'||'bar') as buzz";
        let issues = run(sql);
        assert!(
            !issues.is_empty(),
            "should flag compact || operator: {issues:?}"
        );
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT ('foo' || 'bar') as buzz");
    }

    #[test]
    fn flags_literal_as_spacing() {
        let sql = "SELECT\n    'foo'AS   bar\nFROM foo";
        let issues = run(sql);
        assert!(!issues.is_empty());
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT\n    'foo' AS bar\nFROM foo");
    }

    // --- Function spacing tests ---

    #[test]
    fn does_not_flag_function_call() {
        assert!(run("SELECT foo(5) FROM T1;").is_empty());
        assert!(run("SELECT COUNT(*) FROM tbl\n\n").is_empty());
    }

    // --- Cast operator tests ---

    #[test]
    fn flags_spaced_cast_operator() {
        let sql = "SELECT '1' :: INT;";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag space around ::");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT '1'::INT;");
    }

    // --- JSON arrow tests ---

    #[test]
    fn flags_compact_json_arrow_operator() {
        let sql = "SELECT payload->>'id' FROM t";
        let issues = run(sql);
        assert!(
            issues.len() >= 2,
            "should flag 2+ violations for compact json-arrow"
        );
        assert!(
            issues
                .iter()
                .all(|issue| issue.autofix.as_ref().is_some_and(
                    |autofix| autofix.applicability == IssueAutofixApplicability::Safe
                )),
            "expected safe autofix metadata"
        );

        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "SELECT payload ->> 'id' FROM t");
    }

    // --- EXISTS layout test ---

    #[test]
    fn flags_exists_parenthesis_layout_case() {
        let issues = run("SELECT\n    EXISTS (\n        SELECT 1\n    ) AS has_row");
        assert!(!issues.is_empty());
        assert!(
            issues.iter().all(|issue| issue.autofix.is_none()),
            "EXISTS newline layout violations remain report-only"
        );
    }

    // --- Safe pass cases ---

    #[test]
    fn does_not_flag_spacing_patterns_inside_literals_or_comments() {
        let issues = run("SELECT 'payload->>''id''' AS txt -- EXISTS (\nFROM t");
        assert!(
            issues.is_empty(),
            "should not flag content inside literals/comments: {issues:?}"
        );
    }

    #[test]
    fn does_not_flag_correct_comma_spacing() {
        assert!(run("SELECT 1, 4").is_empty());
    }

    #[test]
    fn does_not_flag_correct_cast() {
        assert!(run("SELECT '1'::INT;").is_empty());
    }

    #[test]
    fn does_not_flag_qualified_identifiers() {
        // Dot-separated identifiers should not have spaces
        assert!(run("SELECT a.b FROM c.d").is_empty());
    }

    #[test]
    fn does_not_flag_newline_after_using() {
        assert!(
            run("select * from a JOIN b USING\n(x)").is_empty(),
            "newline between USING and ( should be acceptable"
        );
    }

    #[test]
    fn flags_cte_newline_after_as() {
        let sql = "WITH a AS\n(\n  select 1\n)\nselect * from a";
        let issues = run(sql);
        assert!(!issues.is_empty(), "should flag AS + newline + (");
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "WITH a AS (\n  select 1\n)\nselect * from a");
    }

    #[test]
    fn flags_cte_newline_and_spaces_after_as() {
        let sql = "WITH a AS\n\n\n    (\n  select 1\n)\nselect * from a";
        let issues = run(sql);
        assert!(!issues.is_empty());
        let fixed = apply_all_issue_autofixes(sql, &issues);
        assert_eq!(fixed, "WITH a AS (\n  select 1\n)\nselect * from a");
    }

    #[test]
    fn does_not_flag_comment_after_as() {
        // When there's a comment between AS and (, it should pass
        assert!(
            run("WITH\na AS -- comment\n(\nselect 1\n)\nselect * from a").is_empty(),
            "comment between AS and ( should be acceptable"
        );
    }
}
