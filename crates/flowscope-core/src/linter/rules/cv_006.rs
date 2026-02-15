//! LINT_CV_006: Statement terminator.
//!
//! Enforce consistent semicolon termination within a SQL document.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

#[derive(Default)]
pub struct ConventionTerminator {
    multiline_newline: bool,
    require_final_semicolon: bool,
}

impl ConventionTerminator {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            multiline_newline: config
                .rule_option_bool(issue_codes::LINT_CV_006, "multiline_newline")
                .unwrap_or(false),
            require_final_semicolon: config
                .rule_option_bool(issue_codes::LINT_CV_006, "require_final_semicolon")
                .unwrap_or(false),
        }
    }
}

impl LintRule for ConventionTerminator {
    fn code(&self) -> &'static str {
        issue_codes::LINT_CV_006
    }

    fn name(&self) -> &'static str {
        "Statement terminator"
    }

    fn description(&self) -> &'static str {
        "Statements must end with a semi-colon."
    }

    fn check(&self, _stmt: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let tokens = tokenize_with_offsets_for_context(ctx);
        let trailing = trailing_info(ctx, tokens.as_deref());
        let has_terminal_semicolon = trailing.semicolon_offset.is_some();

        // require_final_semicolon: last statement without semicolon
        if self.require_final_semicolon
            && is_last_statement(ctx, tokens.as_deref())
            && !has_terminal_semicolon
        {
            let edits = build_require_final_semicolon_edits(ctx, &trailing, self.multiline_newline);
            let span = edits
                .first()
                .map(|e| e.span)
                .unwrap_or_else(|| Span::new(ctx.statement_range.end, ctx.statement_range.end));
            return vec![Issue::info(
                issue_codes::LINT_CV_006,
                "Final statement must end with a semi-colon.",
            )
            .with_statement(ctx.statement_index)
            .with_span(span)
            .with_autofix_edits(IssueAutofixApplicability::Safe, edits)];
        }

        let Some(semicolon_offset) = trailing.semicolon_offset else {
            return Vec::new();
        };

        if self.multiline_newline {
            return self.check_multiline_newline(ctx, &trailing, semicolon_offset);
        }

        // Default mode: semicolon should be immediately after statement (no gap)
        if semicolon_offset != ctx.statement_range.end {
            let edits = build_default_mode_fix(ctx, &trailing, semicolon_offset);
            let mut issue = Issue::info(
                issue_codes::LINT_CV_006,
                "Statement terminator style is inconsistent.",
            )
            .with_statement(ctx.statement_index);
            if !edits.is_empty() {
                let span = edits
                    .first()
                    .map(|e| e.span)
                    .unwrap_or_else(|| Span::new(ctx.statement_range.end, semicolon_offset));
                issue = issue
                    .with_span(span)
                    .with_autofix_edits(IssueAutofixApplicability::Safe, edits);
            }
            return vec![issue];
        }

        Vec::new()
    }
}

impl ConventionTerminator {
    fn check_multiline_newline(
        &self,
        ctx: &LintContext,
        trailing: &TrailingInfo,
        semicolon_offset: usize,
    ) -> Vec<Issue> {
        let tokens = tokenize_with_offsets_for_context(ctx);
        let code_end = actual_code_end(ctx);
        // Determine multiline based on actual code tokens (not comments,
        // not string literal content). Use code_end to exclude trailing
        // comments that the parser may have included in the range.
        let effective_multiline = tokens
            .as_deref()
            .map(|toks| {
                toks.iter()
                    .filter(|t| t.start >= ctx.statement_range.start && t.end <= code_end)
                    .any(|t| matches!(t.token, Token::Whitespace(Whitespace::Newline)))
            })
            .unwrap_or_else(|| {
                count_line_breaks(&ctx.sql[ctx.statement_range.start..code_end]) > 0
            });

        if effective_multiline {
            let tokens_for_check = tokenize_with_offsets_for_context(ctx);
            if is_valid_multiline_newline_style(ctx, trailing, semicolon_offset)
                && !has_standalone_comment_at_end_of_statement(ctx, tokens_for_check.as_deref())
            {
                return Vec::new();
            }
            let edits = build_multiline_newline_fix(ctx, trailing, semicolon_offset);
            let mut issue = Issue::info(
                issue_codes::LINT_CV_006,
                "Multi-line statements must place the semi-colon on a new line.",
            )
            .with_statement(ctx.statement_index);
            if !edits.is_empty() {
                let span = edits
                    .first()
                    .map(|e| e.span)
                    .unwrap_or_else(|| Span::new(ctx.statement_range.end, semicolon_offset + 1));
                issue = issue
                    .with_span(span)
                    .with_autofix_edits(IssueAutofixApplicability::Safe, edits);
            }
            return vec![issue];
        }

        // Single-line statement with multiline_newline: semicolon should be immediately after
        if semicolon_offset != ctx.statement_range.end {
            // Use the default mode fix (same-line placement) for single-line statements.
            let edits = build_default_mode_fix(ctx, trailing, semicolon_offset);
            let mut issue = Issue::info(
                issue_codes::LINT_CV_006,
                "Statement terminator style is inconsistent.",
            )
            .with_statement(ctx.statement_index);
            if !edits.is_empty() {
                let span = edits
                    .first()
                    .map(|e| e.span)
                    .unwrap_or_else(|| Span::new(ctx.statement_range.end, semicolon_offset));
                issue = issue
                    .with_span(span)
                    .with_autofix_edits(IssueAutofixApplicability::Safe, edits);
            }
            return vec![issue];
        }

        Vec::new()
    }
}

/// Check if the semicolon placement is valid for multiline_newline mode.
///
/// Valid placement means the semicolon is on its own line immediately after
/// the last statement content line (which may include a trailing inline
/// comment). The pattern is:
///   - Statement body (may end with inline comment on last line)
///   - Exactly one newline
///   - Semicolon (optionally followed by spacing/comments on the same line)
fn is_valid_multiline_newline_style(
    ctx: &LintContext,
    trailing: &TrailingInfo,
    semicolon_offset: usize,
) -> bool {
    // Find the "anchor": the last non-whitespace content before the semicolon.
    // This could be the statement body end or a trailing inline comment.
    let anchor_end = find_last_content_end_before_semicolon(ctx, trailing, semicolon_offset);

    // The gap between the anchor and the semicolon should have exactly one newline.
    // Note: single-line comment tokens include the trailing newline in their span,
    // so if the anchor is a single-line comment, the newline may be inside the comment span.
    let gap = &ctx.sql[anchor_end..semicolon_offset];

    // Count total newlines from statement end through to the semicolon
    let total_gap = &ctx.sql[ctx.statement_range.end..semicolon_offset];
    let total_newlines = count_line_breaks(total_gap);

    // For valid placement, there should be exactly one newline between the last
    // content and the semicolon. For inline comments that include the trailing newline,
    // the gap may be empty but the comment's newline counts.
    let gap_newlines = count_line_breaks(gap);
    let inline_comment_newlines = if trailing.inline_comment_after_stmt.is_some() {
        // Single-line comments include their trailing newline in the span
        1
    } else {
        0
    };

    let effective_newlines = gap_newlines + inline_comment_newlines;
    if effective_newlines != 1 {
        // If the gap itself has no newlines and no inline comment provides one,
        // and the total gap also has no newlines, it's invalid.
        // However, if total_newlines == 1 and we have an inline comment whose
        // newline accounts for the separation, that's valid.
        if total_newlines != 1 || trailing.inline_comment_after_stmt.is_none() {
            return false;
        }
    }

    // Verify there are no standalone comments between anchor and semicolon
    trailing.comments_before_semicolon.is_empty()
        // And the gap is only whitespace
        && gap.chars().all(|c| c.is_whitespace())
}

/// Find the byte offset of the end of the last meaningful content before
/// the semicolon. This is either the end of the statement range or the end
/// of a trailing inline comment on the last line of the statement.
fn find_last_content_end_before_semicolon(
    ctx: &LintContext,
    trailing: &TrailingInfo,
    semicolon_offset: usize,
) -> usize {
    // If there's a trailing inline comment on the same line as the statement end,
    // it counts as part of the "statement content" for newline-placement purposes.
    if let Some(ref comment) = trailing.inline_comment_after_stmt {
        if comment.end <= semicolon_offset {
            return comment.end;
        }
    }
    ctx.statement_range.end
}

/// Build autofix edits for the default mode (semicolon should be on the same
/// line, immediately after the statement, no gap).
///
/// Uses a two-edit strategy to avoid overlapping with comment protected
/// ranges: (1) insert semicolon at the actual code end, (2) delete the
/// misplaced semicolon. This way neither edit spans over a comment.
fn build_default_mode_fix(
    ctx: &LintContext,
    trailing: &TrailingInfo,
    semicolon_offset: usize,
) -> Vec<IssuePatchEdit> {
    let code_end = actual_code_end(ctx);
    let gap_start = ctx.statement_range.end;
    let semicolon_end = semicolon_offset + 1;

    // If there are no comments between statement and semicolon,
    // just collapse the gap.
    if trailing.comments_before_semicolon.is_empty() && trailing.inline_comment_after_stmt.is_none()
    {
        // Check if the comment is inside the statement range (parser included it)
        if code_end < gap_start {
            // Comment is inside statement range. Use two-edit strategy:
            // 1. Insert ; at code_end   2. Delete old ;
            let mut edits = vec![
                IssuePatchEdit::new(Span::new(code_end, code_end), ";"),
                IssuePatchEdit::new(Span::new(semicolon_offset, semicolon_end), ""),
            ];
            // Also remove whitespace between code_end and the gap_start
            // (only safe whitespace before any comments)
            let pre_gap = &ctx.sql[code_end..gap_start];
            if !pre_gap.is_empty()
                && pre_gap.chars().all(char::is_whitespace)
                && !pre_gap.contains('\n')
            {
                // Whitespace-only gap before the comment — but don't touch
                // if it contains a newline (part of comment token).
            }
            edits.sort_by_key(|e| e.span.start);
            return edits;
        }
        let gap = &ctx.sql[gap_start..semicolon_offset];
        if gap.chars().all(char::is_whitespace) {
            // Replace gap + semicolon with just semicolon
            let span = Span::new(gap_start, semicolon_end);
            return vec![IssuePatchEdit::new(span, ";")];
        }
        return Vec::new();
    }

    // Comments are present between statement end and semicolon.
    // Use two-edit strategy: insert ; at code_end, delete old ;.
    let mut edits = vec![
        IssuePatchEdit::new(Span::new(code_end, code_end), ";"),
        IssuePatchEdit::new(Span::new(semicolon_offset, semicolon_end), ""),
    ];
    edits.sort_by_key(|e| e.span.start);
    edits
}

/// Build autofix edits for multiline_newline mode.
///
/// The semicolon should be on its own new line, indented at the statement level,
/// immediately after the last content line (which may include a trailing inline
/// comment).
///
/// Uses a two-edit strategy to avoid overlapping with comment protected
/// ranges: (1) delete the old semicolon, (2) insert `\n;` at the anchor
/// point (after inline comments, before standalone comments).
fn build_multiline_newline_fix(
    ctx: &LintContext,
    trailing: &TrailingInfo,
    semicolon_offset: usize,
) -> Vec<IssuePatchEdit> {
    let semicolon_end = semicolon_offset + 1;
    let after_semicolon = trailing_content_after_semicolon(ctx, semicolon_offset);

    // Determine the indent for the semicolon line.
    let indent = detect_statement_indent(ctx);

    // Determine anchor for the new semicolon position. Prefer a location
    // outside any comment protected ranges.
    let code_end = actual_code_end(ctx);

    // Check for an inline comment on the same line as code_end (either
    // tracked by trailing_info or inside the statement range).
    let anchor_end = if let Some(ref comment) = trailing.inline_comment_after_stmt {
        comment.end
    } else if let Some(inner_end) = find_inline_comment_in_statement(ctx) {
        inner_end
    } else {
        code_end
    };

    // Check for an inline comment AFTER the semicolon on the same line.
    // Pattern: `foo ; -- comment` → `foo -- comment\n;`
    let after_semi_comment = after_semicolon.trim();
    if !after_semi_comment.is_empty()
        && (after_semi_comment.starts_with("--") || after_semi_comment.starts_with("/*"))
    {
        // The comment after the semicolon needs to stay on the code line.
        // Strategy: remove `;[space]` between code and comment, insert `\n;`
        // after the comment line.
        let mut edits = Vec::new();

        // Delete from the semicolon to the start of the comment text.
        // Find the comment start in the after-semicolon content.
        let comment_start_in_after = after_semicolon
            .find("--")
            .or_else(|| after_semicolon.find("/*"))
            .unwrap_or(0);
        let abs_comment_start = semicolon_end + comment_start_in_after;
        // Delete from semicolon to the comment start (removes `; `)
        edits.push(IssuePatchEdit::new(
            Span::new(semicolon_offset, abs_comment_start),
            "",
        ));

        // Find the end of the after-semicolon content line. Single-line
        // comment tokens include the trailing \n in their span, so advance
        // past it to land outside the comment protected range.
        let mut insert_pos = semicolon_end + after_semicolon.len();
        if insert_pos < ctx.sql.len() && ctx.sql.as_bytes()[insert_pos] == b'\n' {
            insert_pos += 1;
        }
        // Insert ; on its own new line
        let mut rep = String::new();
        if insert_pos == semicolon_end + after_semicolon.len() {
            // No newline found after comment content — add one
            rep.push('\n');
        }
        rep.push_str(&indent);
        rep.push(';');
        edits.push(IssuePatchEdit::new(Span::new(insert_pos, insert_pos), &rep));

        edits.sort_by_key(|e| e.span.start);
        return edits;
    }

    let mut edits = Vec::new();

    // Edit 1: Delete the old semicolon (and any trailing content on its line).
    let delete_end = if after_semicolon.trim().is_empty() {
        semicolon_end + after_semicolon.len()
    } else {
        semicolon_end
    };
    edits.push(IssuePatchEdit::new(
        Span::new(semicolon_offset, delete_end),
        "",
    ));

    // Edit 2: Insert newline + indent + semicolon at the anchor point.
    // Token ends are exclusive, so anchor_end is the first byte OUTSIDE
    // the comment token — safe for zero-width inserts.
    let mut replacement = String::new();
    replacement.push('\n');
    replacement.push_str(&indent);
    replacement.push(';');
    edits.push(IssuePatchEdit::new(
        Span::new(anchor_end, anchor_end),
        &replacement,
    ));

    // Also clean up whitespace between code_end and the semicolon when no
    // comments are involved (simple gap case).
    if trailing.comments_before_semicolon.is_empty()
        && trailing.inline_comment_after_stmt.is_none()
        && code_end == anchor_end
    {
        // Remove any whitespace gap between code end and semicolon that isn't
        // covered by the other edits. For the simple case `stmt_end;` -> `stmt_end\n;`
        // we can just replace `code_end..semicolon_end` directly since there's no
        // comment in between.
        edits.clear();
        let mut rep = String::new();
        rep.push('\n');
        rep.push_str(&indent);
        rep.push(';');
        edits.push(IssuePatchEdit::new(Span::new(code_end, delete_end), &rep));
    }

    edits.sort_by_key(|e| e.span.start);
    edits
}

/// Find the end of the actual SQL code within the statement range, excluding
/// any trailing comments or whitespace that the parser may have included.
///
/// Returns the byte offset immediately after the last non-comment,
/// non-whitespace token that starts within the statement range. Falls back
/// to `statement_range.end` when tokens are unavailable.
fn actual_code_end(ctx: &LintContext) -> usize {
    let tokens = tokenize_with_offsets_for_context(ctx);
    let Some(tokens) = tokens.as_deref() else {
        return ctx.statement_range.end;
    };
    let last_code = tokens.iter().rfind(|t| {
        t.start >= ctx.statement_range.start
            && t.start < ctx.statement_range.end
            && !is_spacing_whitespace(&t.token)
            && !is_comment_token(&t.token)
    });
    last_code.map_or(ctx.statement_range.end, |t| t.end)
}

/// Build autofix edits for require_final_semicolon when no semicolon exists.
///
/// Inserts the semicolon at the actual code end (before any trailing
/// comments) so the edit does not overlap comment protected ranges.
fn build_require_final_semicolon_edits(
    ctx: &LintContext,
    trailing: &TrailingInfo,
    multiline_newline: bool,
) -> Vec<IssuePatchEdit> {
    let code_end = actual_code_end(ctx);
    let is_multiline = count_line_breaks(&ctx.sql[ctx.statement_range.start..code_end]) > 0;

    if multiline_newline && is_multiline {
        // Multiline + require_final: insert semicolon on its own new line after the
        // last content (including any trailing inline comment).
        let anchor_end = if let Some(ref comment) = trailing.inline_comment_after_stmt {
            comment.end
        } else if let Some(inner_comment) = find_inline_comment_in_statement(ctx) {
            inner_comment
        } else {
            code_end
        };

        let indent = detect_statement_indent(ctx);

        // Token ends are exclusive, so anchor_end is the first byte OUTSIDE
        // the comment token — safe for zero-width inserts.
        let mut replacement = String::new();
        replacement.push('\n');
        replacement.push_str(&indent);
        replacement.push(';');

        let span = Span::new(anchor_end, anchor_end);
        return vec![IssuePatchEdit::new(span, &replacement)];
    }

    // Insert semicolon at the actual code end to avoid overlapping with
    // comment protected ranges.
    let insert_span = Span::new(code_end, code_end);
    vec![IssuePatchEdit::new(insert_span, ";")]
}

/// Find the end of an inline comment on the last line of code within the
/// statement range (where the parser included the comment in the range).
fn find_inline_comment_in_statement(ctx: &LintContext) -> Option<usize> {
    let tokens = tokenize_with_offsets_for_context(ctx)?;
    let code_end = tokens.iter().rfind(|t| {
        t.start >= ctx.statement_range.start
            && t.start < ctx.statement_range.end
            && !is_spacing_whitespace(&t.token)
            && !is_comment_token(&t.token)
    })?;
    let code_end_line = offset_to_line_number(ctx.sql, code_end.end);

    // Look for a single-line comment starting on the same line as the last code token
    let inline = tokens.iter().find(|t| {
        t.start > code_end.end
            && t.start < ctx.statement_range.end
            && is_single_line_comment(&t.token)
            && offset_to_line_number(ctx.sql, t.start) == code_end_line
    })?;
    Some(inline.end)
}

/// Detect the indentation level of the first line of the statement.
fn detect_statement_indent(ctx: &LintContext) -> String {
    let start = ctx.statement_range.start;
    // Walk backwards from statement start to find the beginning of the line
    let line_start = ctx.sql[..start].rfind('\n').map(|pos| pos + 1).unwrap_or(0);
    let prefix = &ctx.sql[line_start..start];
    // Extract leading whitespace
    let indent: String = prefix.chars().take_while(|c| c.is_whitespace()).collect();
    indent
}

/// Get content after the semicolon (typically trailing comments/whitespace on the
/// same line or rest of the source up to next statement).
fn trailing_content_after_semicolon<'a>(
    ctx: &'a LintContext<'a>,
    semicolon_offset: usize,
) -> &'a str {
    let after = semicolon_offset + 1;
    // Find the end of the trailing content: up to the next newline or end of document
    // that is still within the "trailing" zone (not part of the next statement).
    let rest = &ctx.sql[after..];
    // Take content up to the end of the line
    if let Some(nl_pos) = rest.find('\n') {
        &rest[..nl_pos]
    } else {
        rest
    }
}

/// Information about the trailing tokens after a statement.
struct TrailingInfo {
    /// Byte offset of the terminal semicolon, if present.
    semicolon_offset: Option<usize>,
    /// Inline comment on the same line as statement end, before the semicolon
    /// or before EOF (for require_final_semicolon cases).
    inline_comment_after_stmt: Option<CommentSpan>,
    /// Standalone comments (on their own lines) between statement and semicolon.
    comments_before_semicolon: Vec<CommentSpan>,
}

#[derive(Clone)]
struct CommentSpan {
    end: usize,
}

/// Analyze the trailing tokens after statement_range.end to collect
/// information about semicolons, comments, and whitespace.
fn trailing_info(ctx: &LintContext, tokens: Option<&[LocatedToken]>) -> TrailingInfo {
    let Some(tokens) = tokens else {
        return TrailingInfo {
            semicolon_offset: None,
            inline_comment_after_stmt: None,
            comments_before_semicolon: Vec::new(),
        };
    };

    let stmt_end = ctx.statement_range.end;
    let stmt_end_line = offset_to_line_number(ctx.sql, stmt_end);

    let mut semicolon_offset = None;
    let mut inline_comment_after_stmt = None;
    let mut comments_before_semicolon = Vec::new();
    let mut found_semicolon = false;

    for token in tokens.iter().filter(|t| t.start >= stmt_end) {
        match &token.token {
            Token::SemiColon if !found_semicolon => {
                semicolon_offset = Some(token.start);
                found_semicolon = true;
            }
            trivia if is_trivia_token(trivia) => {
                if !found_semicolon && is_comment_token(trivia) {
                    let token_line = offset_to_line_number(ctx.sql, token.start);
                    let span = CommentSpan { end: token.end };
                    if token_line == stmt_end_line
                        && inline_comment_after_stmt.is_none()
                        && is_single_line_comment(trivia)
                    {
                        inline_comment_after_stmt = Some(span);
                    } else {
                        comments_before_semicolon.push(span);
                    }
                }
            }
            _ => {
                if !found_semicolon {
                    break;
                }
                // Hit non-trivia after semicolon; stop.
                break;
            }
        }
    }

    TrailingInfo {
        semicolon_offset,
        inline_comment_after_stmt,
        comments_before_semicolon,
    }
}

fn is_single_line_comment(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::SingleLineComment { .. })
    )
}

fn offset_to_line_number(sql: &str, offset: usize) -> usize {
    sql.as_bytes()
        .iter()
        .take(offset.min(sql.len()))
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn is_last_statement(ctx: &LintContext, tokens: Option<&[LocatedToken]>) -> bool {
    let Some(tokens) = tokens else {
        return false;
    };
    for token in tokens
        .iter()
        .filter(|token| token.start >= ctx.statement_range.end)
    {
        if matches!(token.token, Token::SemiColon)
            || is_trivia_token(&token.token)
            || is_go_batch_separator(token, tokens, ctx.dialect())
        {
            continue;
        }
        return false;
    }
    true
}

/// Checks if the statement range ends with a standalone comment on its own line.
/// This detects cases where the parser includes a trailing comment in the
/// statement range (e.g., `SELECT a\nFROM foo\n-- trailing`) where `-- trailing`
/// is on a separate line from the actual code.
fn has_standalone_comment_at_end_of_statement(
    ctx: &LintContext,
    tokens: Option<&[LocatedToken]>,
) -> bool {
    let Some(tokens) = tokens else {
        return false;
    };

    // Find the last non-whitespace token that starts within the statement range.
    // Note: comment tokens may extend past stmt_end because single-line comments
    // include the trailing newline in their span.
    let last_token = tokens.iter().rfind(|t| {
        t.start >= ctx.statement_range.start
            && t.start < ctx.statement_range.end
            && !is_spacing_whitespace(&t.token)
    });

    let Some(last) = last_token else {
        return false;
    };

    if !is_comment_token(&last.token) {
        return false;
    }

    // Check if this comment is on a different line from the previous non-whitespace token
    let prev_token = tokens.iter().rfind(|t| {
        t.start >= ctx.statement_range.start
            && t.start < last.start
            && !is_spacing_whitespace(&t.token)
            && !is_comment_token(&t.token)
    });

    let Some(prev) = prev_token else {
        return false;
    };

    // If the comment starts on a different line than the previous code token, it's standalone
    offset_to_line_number(ctx.sql, last.start) != offset_to_line_number(ctx.sql, prev.start)
}

struct LocatedToken {
    token: Token,
    start: usize,
    end: usize,
    start_line: usize,
    end_line: usize,
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
                        start_line: token.span.start.line as usize,
                        end_line: token.span.end.line as usize,
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

fn tokenize_with_offsets(sql: &str, dialect: Dialect) -> Option<Vec<LocatedToken>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let tokens = tokenizer.tokenize_with_location().ok()?;

    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let Some((start, end)) = token_with_span_offsets(sql, &token) else {
            continue;
        };
        out.push(LocatedToken {
            token: token.token,
            start,
            end,
            start_line: token.span.start.line as usize,
            end_line: token.span.end.line as usize,
        });
    }

    Some(out)
}

fn is_comment_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_))
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

fn is_trivia_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
            | Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_))
    )
}

fn is_spacing_whitespace(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
    )
}

fn is_go_batch_separator(token: &LocatedToken, tokens: &[LocatedToken], dialect: Dialect) -> bool {
    if dialect != Dialect::Mssql {
        return false;
    }
    let Token::Word(word) = &token.token else {
        return false;
    };
    if !word.value.eq_ignore_ascii_case("GO") {
        return false;
    }
    if token.start_line != token.end_line {
        return false;
    }

    let line = token.start_line;
    let mut go_count = 0usize;
    for candidate in tokens {
        if candidate.start_line != line {
            continue;
        }
        if is_spacing_whitespace(&candidate.token) {
            continue;
        }
        match &candidate.token {
            Token::Word(word) if word.value.eq_ignore_ascii_case("GO") => {
                go_count += 1;
            }
            _ => return false,
        }
    }

    go_count == 1
}

fn count_line_breaks(text: &str) -> usize {
    let mut count = 0usize;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\n' {
            count += 1;
            continue;
        }
        if ch == '\r' {
            count += 1;
            if matches!(chars.peek(), Some('\n')) {
                let _ = chars.next();
            }
        }
    }
    count
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
    use crate::linter::rule::with_active_dialect;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let stmts = parse_sql(sql).expect("parse");
        let rule = ConventionTerminator::default();
        stmts
            .iter()
            .enumerate()
            .flat_map(|(index, stmt)| {
                rule.check(
                    stmt,
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

    fn statement_is_multiline(ctx: &LintContext, tokens: Option<&[LocatedToken]>) -> bool {
        let Some(tokens) = tokens else {
            return count_line_breaks(ctx.statement_sql()) > 0;
        };

        tokens
            .iter()
            .filter(|token| {
                token.start >= ctx.statement_range.start && token.end <= ctx.statement_range.end
            })
            .any(|token| is_multiline_trivia_token(&token.token))
    }

    fn is_multiline_trivia_token(token: &Token) -> bool {
        matches!(
            token,
            Token::Whitespace(Whitespace::Newline)
                | Token::Whitespace(Whitespace::SingleLineComment { .. })
                | Token::Whitespace(Whitespace::MultiLineComment(_))
        )
    }

    #[test]
    fn default_allows_missing_final_semicolon_in_multi_statement_file() {
        let issues = run("select 1; select 2");
        assert!(issues.is_empty());
    }

    #[test]
    fn allows_consistent_terminated_statements() {
        let issues = run("select 1; select 2;");
        assert!(issues.is_empty());
    }

    #[test]
    fn require_final_semicolon_flags_last_statement_without_terminator() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"require_final_semicolon": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT 1";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0..sql.len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
        assert_eq!(
            issues[0]
                .autofix
                .as_ref()
                .map(|autofix| autofix.edits.len()),
            Some(1)
        );
        assert_eq!(
            issues[0]
                .autofix
                .as_ref()
                .map(|autofix| autofix.applicability),
            Some(IssueAutofixApplicability::Safe)
        );
        assert_eq!(
            issues[0]
                .autofix
                .as_ref()
                .and_then(|autofix| autofix.edits.first())
                .map(|edit| edit.replacement.as_str()),
            Some(";")
        );
    }

    #[test]
    fn multiline_newline_flags_inline_semicolon_for_multiline_statement() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CV_006".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT\n  1;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT\n  1".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
    }

    #[test]
    fn default_flags_space_before_semicolon() {
        let sql = "SELECT a FROM foo  ;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = ConventionTerminator::default().check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a FROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a FROM foo;");
    }

    #[test]
    fn multiline_newline_flags_extra_blank_line_before_semicolon() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a\nFROM foo\n\n;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a\nFROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
    }

    #[test]
    fn multiline_newline_flags_comment_before_semicolon() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a\nFROM foo\n-- trailing\n;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a\nFROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
    }

    #[test]
    fn multiline_newline_flags_trailing_comment_inside_statement_range() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a\nFROM foo\n-- trailing\n;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a\nFROM foo\n-- trailing".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
    }

    #[test]
    fn require_final_semicolon_flags_missing_semicolon_before_trailing_go_batch_separator() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"require_final_semicolon": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let stmt = &parse_sql("SELECT 1").expect("parse")[0];
        let sql = "SELECT 1\nGO\n";
        let issues = with_active_dialect(Dialect::Mssql, || {
            rule.check(
                stmt,
                &LintContext {
                    sql,
                    statement_range: 0.."SELECT 1".len(),
                    statement_index: 0,
                },
            )
        });
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_CV_006);
    }

    #[test]
    fn require_final_semicolon_does_not_flag_non_last_statement_before_go_batch_separator() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"require_final_semicolon": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let stmt = &parse_sql("SELECT 1").expect("parse")[0];
        let sql = "SELECT 1\nGO\nSELECT 2;";
        let issues = with_active_dialect(Dialect::Mssql, || {
            rule.check(
                stmt,
                &LintContext {
                    sql,
                    statement_range: 0.."SELECT 1".len(),
                    statement_index: 0,
                },
            )
        });
        assert!(issues.is_empty());
    }

    #[test]
    fn require_final_semicolon_does_not_treat_inline_comment_go_as_batch_separator() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"require_final_semicolon": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let stmt = &parse_sql("SELECT 1").expect("parse")[0];
        let sql = "SELECT 1\nGO -- not a standalone separator\n";
        let issues = with_active_dialect(Dialect::Mssql, || {
            rule.check(
                stmt,
                &LintContext {
                    sql,
                    statement_range: 0.."SELECT 1".len(),
                    statement_index: 0,
                },
            )
        });
        assert!(issues.is_empty());
    }

    #[test]
    fn multiline_newline_allows_newline_within_string_literal() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT 'line1\nline2';";
        let stmt = &parse_sql(sql).expect("parse")[0];
        let issues = rule.check(
            stmt,
            &LintContext {
                sql,
                statement_range: 0.."SELECT 'line1\nline2'".len(),
                statement_index: 0,
            },
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn statement_is_multiline_fallback_handles_crlf_line_breaks() {
        let sql = "SELECT\r\n  1";
        let ctx = LintContext {
            sql,
            statement_range: 0..sql.len(),
            statement_index: 0,
        };
        assert!(statement_is_multiline(&ctx, None));
    }

    #[test]
    fn multiline_newline_allows_inline_comment_before_newline_semicolon() {
        // test_pass_newline_inline_comment: should not flag
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a\nFROM foo -- inline comment\n;";
        let stmts = parse_sql(sql).expect("parse");
        let stmt_range = 0.."SELECT a\nFROM foo".len();
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: stmt_range,
                statement_index: 0,
            },
        );
        assert!(
            issues.is_empty(),
            "Should not flag: inline comment before newline+semicolon is valid in multiline_newline mode"
        );
    }

    #[test]
    fn default_mode_fix_newline_before_semicolon() {
        // test_fail_newline_semi_colon_default
        let sql = "SELECT a FROM foo\n;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = ConventionTerminator::default().check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a FROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a FROM foo;");
    }

    #[test]
    fn default_mode_fix_comment_then_semicolon() {
        // test_fail_same_line_inline_comment
        // Two-edit strategy: insert ; at code_end, delete old ;
        // The \n between comment and old ; stays (part of comment token).
        let sql = "SELECT a FROM foo -- inline comment\n;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = ConventionTerminator::default().check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a FROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a FROM foo; -- inline comment\n");
    }

    #[test]
    fn require_final_semicolon_with_inline_comment() {
        // test_fail_final_semi_colon_same_line_inline_comment
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"require_final_semicolon": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a FROM foo -- inline comment\n";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a FROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a FROM foo; -- inline comment\n");
    }

    #[test]
    fn multiline_newline_fix_moves_semicolon_to_new_line() {
        // test_fail_semi_colon_same_line_custom_newline
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a\nFROM foo;";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a\nFROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a\nFROM foo\n;");
    }

    #[test]
    fn require_final_multiline_adds_semicolon_on_new_line() {
        // test_fail_no_semi_colon_custom_require_multiline
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.terminator".to_string(),
                serde_json::json!({"require_final_semicolon": true, "multiline_newline": true}),
            )]),
        };
        let rule = ConventionTerminator::from_config(&config);
        let sql = "SELECT a\nFROM foo\n";
        let stmts = parse_sql(sql).expect("parse");
        let issues = rule.check(
            &stmts[0],
            &LintContext {
                sql,
                statement_range: 0.."SELECT a\nFROM foo".len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a\nFROM foo\n;\n");
    }
}
