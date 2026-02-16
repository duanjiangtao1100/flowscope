//! LINT_LT_004: Layout commas.
//!
//! SQLFluff LT04 parity (current scope): detect compact or leading-space comma
//! patterns.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::Statement;
use sqlparser::tokenizer::{Location, Span, Token, TokenWithSpan, Tokenizer, Whitespace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommaLinePosition {
    Trailing,
    Leading,
}

impl CommaLinePosition {
    fn from_config(config: &LintConfig) -> Self {
        if let Some(value) = config.rule_option_str(issue_codes::LINT_LT_004, "line_position") {
            return match value.to_ascii_lowercase().as_str() {
                "leading" => Self::Leading,
                _ => Self::Trailing,
            };
        }

        // SQLFluff legacy compatibility (`trailing`/`leading`).
        match config
            .rule_option_str(issue_codes::LINT_LT_004, "comma_style")
            .unwrap_or("trailing")
            .to_ascii_lowercase()
            .as_str()
        {
            "leading" => Self::Leading,
            _ => Self::Trailing,
        }
    }
}

pub struct LayoutCommas {
    line_position: CommaLinePosition,
}

impl LayoutCommas {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            line_position: CommaLinePosition::from_config(config),
        }
    }
}

impl Default for LayoutCommas {
    fn default() -> Self {
        Self {
            line_position: CommaLinePosition::Trailing,
        }
    }
}

impl LintRule for LayoutCommas {
    fn code(&self) -> &'static str {
        issue_codes::LINT_LT_004
    }

    fn name(&self) -> &'static str {
        "Layout commas"
    }

    fn description(&self) -> &'static str {
        "Leading/Trailing comma enforcement."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let violations = comma_spacing_violations(ctx, self.line_position);
        if violations.is_empty() {
            return Vec::new();
        }

        // Merge all violation edits into a single issue anchored at the first
        // comma, so the fix engine can apply them in one pass.
        let ((start, end), _) = &violations[0];
        let all_edits: Vec<Lt04AutofixEdit> = violations
            .iter()
            .flat_map(|(_, edits)| edits.iter().cloned())
            .collect();

        let mut issue = Issue::info(
            issue_codes::LINT_LT_004,
            "Comma spacing appears inconsistent.",
        )
        .with_statement(ctx.statement_index)
        .with_span(ctx.span_from_statement_offset(*start, *end));
        if !all_edits.is_empty() {
            let edits = all_edits
                .into_iter()
                .map(|(edit_start, edit_end, replacement)| {
                    IssuePatchEdit::new(
                        ctx.span_from_statement_offset(edit_start, edit_end),
                        replacement,
                    )
                })
                .collect();
            issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, edits);
        }
        vec![issue]
    }
}

type Lt04Span = (usize, usize);
type Lt04AutofixEdit = (usize, usize, String);
type Lt04Violation = (Lt04Span, Vec<Lt04AutofixEdit>);

fn comma_spacing_violations(
    ctx: &LintContext,
    line_position: CommaLinePosition,
) -> Vec<Lt04Violation> {
    let tokens =
        tokenized_for_context(ctx).or_else(|| tokenized(ctx.statement_sql(), ctx.dialect()));
    let Some(tokens) = tokens else {
        return Vec::new();
    };
    let sql = ctx.statement_sql();
    let mut violations = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        if !matches!(token.token, Token::Comma) {
            continue;
        }

        let prev_sig_idx = tokens[..index]
            .iter()
            .rposition(|candidate| !is_trivia_token(&candidate.token));
        let Some(prev_sig_idx) = prev_sig_idx else {
            continue;
        };
        let next_sig_idx = tokens
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, candidate)| !is_trivia_token(&candidate.token))
            .map(|(idx, _)| idx);
        let Some(next_sig_idx) = next_sig_idx else {
            continue;
        };
        let Some((comma_start, comma_end)) = token_with_span_offsets(sql, token) else {
            continue;
        };

        let comma_line = token.span.start.line;
        let prev_line = tokens[prev_sig_idx].span.end.line;
        let next_line = tokens[next_sig_idx].span.start.line;
        let line_break_before = prev_line < comma_line;
        let line_break_after = next_line > comma_line;

        let line_position_violation = match line_position {
            CommaLinePosition::Trailing => line_break_before && !line_break_after,
            CommaLinePosition::Leading => line_break_after && !line_break_before,
        };
        if line_position_violation {
            let edits = safe_comma_line_move_edits(
                sql,
                &tokens,
                index,
                prev_sig_idx,
                next_sig_idx,
                line_position,
            )
            .unwrap_or_default();
            violations.push(((comma_start, comma_end), edits));
            continue;
        }

        let mut edits = Vec::new();
        let mut violation = false;

        // Inline comma cases should have no pre-comma spacing.
        let has_pre_inline_space = prev_line == comma_line
            && tokens[prev_sig_idx + 1..index]
                .iter()
                .any(|candidate| is_inline_space_token(&candidate.token));
        if has_pre_inline_space {
            violation = true;
            if let Some((gap_start, gap_end)) =
                safe_inline_gap_between(sql, &tokens[prev_sig_idx], token)
            {
                if gap_start < gap_end {
                    edits.push((gap_start, gap_end, String::new()));
                }
            }
        }

        // Inline comma cases should have spacing after comma.
        // Skip when the comma is already in the preferred line position (e.g.
        // leading-mode comma at line start: `\n    ,b` is correctly positioned;
        // adding a space would contradict line-position intent).
        let comma_in_preferred_position = match line_position {
            CommaLinePosition::Leading => line_break_before,
            CommaLinePosition::Trailing => line_break_after,
        };
        let missing_post_inline_space = !comma_in_preferred_position
            && next_line == comma_line
            && !tokens[index + 1..next_sig_idx]
                .iter()
                .any(|candidate| is_inline_space_token(&candidate.token));
        if missing_post_inline_space {
            violation = true;
            if let Some((gap_start, gap_end)) =
                safe_inline_gap_between(sql, token, &tokens[next_sig_idx])
            {
                edits.push((gap_start, gap_end, " ".to_string()));
            }
        }

        if violation {
            violations.push(((comma_start, comma_end), edits));
        }
    }

    violations
}

/// Generate autofix edits to move a comma across a line break.
///
/// For `Trailing` mode (comma should be trailing): input is `a\n  , b` → `a,\n  b`.
/// For `Leading` mode (comma should be leading): input is `a,\n  b` → `a\n  , b`.
///
/// Edits are split so they do not span comment tokens, which the fix engine
/// treats as protected ranges.
fn safe_comma_line_move_edits(
    sql: &str,
    tokens: &[TokenWithSpan],
    comma_idx: usize,
    prev_sig_idx: usize,
    next_sig_idx: usize,
    line_position: CommaLinePosition,
) -> Option<Vec<Lt04AutofixEdit>> {
    let (_, prev_end) = token_with_span_offsets(sql, &tokens[prev_sig_idx])?;
    let (comma_start, comma_end) = token_with_span_offsets(sql, &tokens[comma_idx])?;
    let (next_start, _) = token_with_span_offsets(sql, &tokens[next_sig_idx])?;

    if prev_end > comma_start || comma_end > next_start || next_start > sql.len() {
        return None;
    }

    let before_gap = &sql[prev_end..comma_start];
    let after_gap = &sql[comma_end..next_start];
    let has_comments =
        gap_has_comment(before_gap) || gap_has_comment(after_gap);

    if !has_comments {
        // Simple case: no comments in either gap.
        if !before_gap.chars().all(char::is_whitespace)
            || !after_gap.chars().all(char::is_whitespace)
        {
            return None;
        }
        let indent = line_indent_at(sql, next_start);
        return match line_position {
            CommaLinePosition::Trailing => {
                Some(vec![(prev_end, next_start, format!(",\n{indent}"))])
            }
            CommaLinePosition::Leading => {
                Some(vec![(prev_end, next_start, format!("\n{indent}, "))])
            }
        };
    }

    // Comment-aware comma move: produce surgical edits that avoid comment spans.
    //
    // Strategy: delete the comma + whitespace at its old position, then insert
    // the comma + adjusted whitespace at the new position. Comments stay
    // untouched.
    let indent = line_indent_at(sql, next_start);

    match line_position {
        CommaLinePosition::Trailing => {
            // Currently leading: comma is on the next line.
            // Example: `a\n    , b -- comment` → `a,\n    b -- comment`
            // Example: `a--comment\n    , b` → `a,--comment\n    b`
            let mut edits = Vec::new();

            // 1) Insert comma right after previous significant token.
            //    If a comment starts exactly at prev_end (no gap), extend the
            //    edit one byte into the preceding token so it becomes a
            //    replacement rather than a zero-width insert touching the
            //    comment's protected range.
            if prev_end > 0 && gap_has_comment(&sql[prev_end..comma_start]) {
                let anchor = prev_end - 1;
                let ch = &sql[anchor..prev_end];
                edits.push((anchor, prev_end, format!("{ch},")));
            } else {
                edits.push((prev_end, prev_end, ",".to_string()));
            }

            // 2) Delete the comma and surrounding whitespace on its line,
            //    taking care not to touch any comment.
            //    The region to clean is the whitespace-only portion at the
            //    start of the comma's line up to (and including) the comma,
            //    plus any trailing whitespace after the comma on the same line
            //    (but not if there's a comment after it on that line).
            let delete_start = line_start_after_newline(sql, comma_start);
            let delete_end = skip_inline_whitespace(sql, comma_end);
            edits.push((delete_start, delete_end, indent.to_string()));

            Some(edits)
        }
        CommaLinePosition::Leading => {
            // Currently trailing: comma is at the end of the previous line.
            // Example: `a,\n    b` → `a\n    , b`
            // Example: `a.baz,\n    -- comment\n     a.bar` → `a.baz\n    -- comment\n     , a.bar`
            let mut edits = Vec::new();

            // 1) Delete the comma (and any whitespace between prev token end
            //    and comma if on the same line).
            let delete_start = whitespace_before_on_same_line(sql, comma_start, prev_end);
            edits.push((delete_start, comma_end, String::new()));

            // 2) Insert `, ` before the next significant token.
            let insert_pos = line_start_after_newline(sql, next_start);
            edits.push((insert_pos, next_start, format!("{indent}, ")));

            Some(edits)
        }
    }
}

/// Check if a gap string contains a comment.
fn gap_has_comment(gap: &str) -> bool {
    gap.contains("--") || gap.contains("/*")
}

/// Return the position right after the last newline before `offset`, i.e. the
/// start of the line containing `offset`.
fn line_start_after_newline(sql: &str, offset: usize) -> usize {
    sql[..offset]
        .rfind('\n')
        .map(|pos| pos + 1)
        .unwrap_or(0)
}

/// Skip inline whitespace (spaces and tabs) starting at `offset`.
fn skip_inline_whitespace(sql: &str, offset: usize) -> usize {
    let mut pos = offset;
    let bytes = sql.as_bytes();
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    pos
}

/// Walk backwards from `offset` over spaces/tabs on the same line, stopping at
/// `floor` or a newline.
fn whitespace_before_on_same_line(sql: &str, offset: usize, floor: usize) -> usize {
    let mut pos = offset;
    let bytes = sql.as_bytes();
    while pos > floor && (bytes[pos - 1] == b' ' || bytes[pos - 1] == b'\t') {
        pos -= 1;
    }
    pos
}

/// Extract the leading whitespace (indent) for the line containing `offset`.
fn line_indent_at(sql: &str, offset: usize) -> &str {
    let line_start = sql[..offset]
        .rfind('\n')
        .map(|pos| pos + 1)
        .unwrap_or(0);
    let indent_end = sql[line_start..]
        .find(|ch: char| !ch.is_whitespace() || ch == '\n')
        .map(|pos| line_start + pos)
        .unwrap_or(offset);
    &sql[line_start..indent_end]
}

fn safe_inline_gap_between(
    sql: &str,
    left: &TokenWithSpan,
    right: &TokenWithSpan,
) -> Option<(usize, usize)> {
    let (_, start) = token_with_span_offsets(sql, left)?;
    let (end, _) = token_with_span_offsets(sql, right)?;
    if start > end || end > sql.len() {
        return None;
    }

    let gap = &sql[start..end];
    if gap.chars().all(char::is_whitespace) && !gap.contains('\n') && !gap.contains('\r') {
        Some((start, end))
    } else {
        None
    }
}

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

fn is_trivia_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Newline | Whitespace::Tab)
            | Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_))
    )
}

fn is_inline_space_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab)
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
        let mut line = 1usize;
        let mut column = 1usize;
        for ch in sql.chars() {
            if ch == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
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

    None
}

fn relative_location(
    location: Location,
    statement_start_line: usize,
    statement_start_column: usize,
) -> Option<Location> {
    let line = location.line as usize;
    let column = location.column as usize;
    if line < statement_start_line {
        return None;
    }

    if line == statement_start_line {
        if column < statement_start_column {
            return None;
        }
        return Some(Location::new(
            1,
            (column - statement_start_column + 1) as u64,
        ));
    }

    Some(Location::new(
        (line - statement_start_line + 1) as u64,
        column as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::config::LintConfig;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run_with_rule(sql: &str, rule: &LayoutCommas) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
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

    fn run(sql: &str) -> Vec<Issue> {
        run_with_rule(sql, &LayoutCommas::default())
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
    fn flags_tight_comma_spacing() {
        let sql = "SELECT a,b FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_004);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a, b FROM t");
    }

    #[test]
    fn does_not_flag_spaced_commas() {
        assert!(run("SELECT a, b FROM t").is_empty());
    }

    #[test]
    fn does_not_flag_comma_inside_string_literal() {
        assert!(run("SELECT 'a,b' AS txt, b FROM t").is_empty());
    }

    #[test]
    fn comma_with_inline_comment_gap_is_report_only() {
        let sql = "SELECT a,/* comment */b FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "comment-bearing comma spacing remains report-only in conservative LT004 migration"
        );
    }

    #[test]
    fn leading_line_position_flags_trailing_line_comma() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "layout.commas".to_string(),
                serde_json::json!({"line_position": "leading"}),
            )]),
        };
        let issues = run_with_rule("SELECT a,\n b FROM t", &LayoutCommas::from_config(&config));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_004);
    }

    #[test]
    fn trailing_mode_moves_leading_comma_to_trailing() {
        let sql = "SELECT\n    a\n    , b\nFROM c";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT\n    a,\n    b\nFROM c");
    }

    #[test]
    fn leading_mode_moves_trailing_comma_to_leading() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "layout.commas".to_string(),
                serde_json::json!({"line_position": "leading"}),
            )]),
        };
        let sql = "SELECT\n    a,\n    b\nFROM c";
        let issues = run_with_rule(sql, &LayoutCommas::from_config(&config));
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT\n    a\n    , b\nFROM c");
    }

    #[test]
    fn legacy_comma_style_leading_is_respected() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_LT_004".to_string(),
                serde_json::json!({"comma_style": "leading"}),
            )]),
        };
        let issues = run_with_rule("SELECT a\n, b FROM t", &LayoutCommas::from_config(&config));
        assert!(issues.is_empty());
    }

    #[test]
    fn trailing_mode_moves_leading_commas_with_inline_comment() {
        let sql = "SELECT\n    a\n    , b -- inline comment\n    , c\n    /* non inline comment */\n    , d\nFROM e";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(
            fixed,
            "SELECT\n    a,\n    b, -- inline comment\n    c,\n    /* non inline comment */\n    d\nFROM e"
        );
    }

    #[test]
    fn trailing_mode_moves_leading_comma_with_comment_before() {
        let sql = "SELECT a--comment\n    , b\nFROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a,--comment\n    b\nFROM t");
    }

    #[test]
    fn trailing_mode_multiple_leading_commas_fixed() {
        let sql = "SELECT\n    field_1\n    ,   field_2\n    ,field_3\nFROM a";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].autofix.is_some(), "autofix metadata");
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT\n    field_1,\n    field_2,\n    field_3\nFROM a");
    }
}
