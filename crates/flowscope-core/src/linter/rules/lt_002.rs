//! LINT_LT_002: Layout indent.
//!
//! SQLFluff LT02 parity: flag structural indentation violations (clause
//! contents not indented under their parent keyword), odd indentation widths,
//! mixed tab/space indentation, and wrong indent style.

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::Statement;
use sqlparser::keywords::Keyword;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};
use std::collections::{BTreeMap, HashSet};

pub struct LayoutIndent {
    indent_unit: usize,
    tab_space_size: usize,
    indent_style: IndentStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndentStyle {
    Spaces,
    Tabs,
}

impl LayoutIndent {
    pub fn from_config(config: &LintConfig) -> Self {
        let tab_space_size = config
            .rule_option_usize(issue_codes::LINT_LT_002, "tab_space_size")
            .or_else(|| config.section_option_usize("indentation", "tab_space_size"))
            .or_else(|| config.section_option_usize("rules", "tab_space_size"))
            .unwrap_or(4)
            .max(1);

        let indent_style = match config
            .rule_option_str(issue_codes::LINT_LT_002, "indent_unit")
            .or_else(|| config.section_option_str("indentation", "indent_unit"))
            .or_else(|| config.section_option_str("rules", "indent_unit"))
        {
            Some(value) if value.eq_ignore_ascii_case("tab") => IndentStyle::Tabs,
            _ => IndentStyle::Spaces,
        };

        let indent_unit_numeric = config
            .rule_option_usize(issue_codes::LINT_LT_002, "indent_unit")
            .or_else(|| config.section_option_usize("indentation", "indent_unit"))
            .or_else(|| config.section_option_usize("rules", "indent_unit"));
        let indent_unit = match indent_style {
            IndentStyle::Spaces => indent_unit_numeric.unwrap_or(4).max(1),
            IndentStyle::Tabs => indent_unit_numeric.unwrap_or(tab_space_size).max(1),
        };
        Self {
            indent_unit,
            tab_space_size,
            indent_style,
        }
    }
}

impl Default for LayoutIndent {
    fn default() -> Self {
        Self {
            indent_unit: 4,
            tab_space_size: 4,
            indent_style: IndentStyle::Spaces,
        }
    }
}

impl LintRule for LayoutIndent {
    fn code(&self) -> &'static str {
        issue_codes::LINT_LT_002
    }

    fn name(&self) -> &'static str {
        "Layout indent"
    }

    fn description(&self) -> &'static str {
        "Incorrect Indentation."
    }

    fn check(&self, _statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let snapshots = line_indent_snapshots(ctx, self.tab_space_size);
        let mut has_violation = first_line_is_indented(ctx);

        // Syntactic checks: odd width, mixed chars, wrong style.
        for snapshot in &snapshots {
            let indent = snapshot.indent;

            if snapshot.line_index == 0 && indent.width > 0 {
                has_violation = true;
                break;
            }

            if indent.has_mixed_indent_chars {
                has_violation = true;
                break;
            }

            if matches!(self.indent_style, IndentStyle::Spaces) && indent.tab_count > 0 {
                has_violation = true;
                break;
            }

            if matches!(self.indent_style, IndentStyle::Tabs) && indent.space_count > 0 {
                has_violation = true;
                break;
            }

            if indent.width > 0 && indent.width % self.indent_unit != 0 {
                has_violation = true;
                break;
            }
        }

        // Structural check: clause contents must be indented under their
        // parent keyword (e.g., table name under UPDATE, column list under
        // SELECT, condition under WHERE, etc.).
        let structural_edits = if !has_violation {
            let edits = structural_indent_edits(
                ctx,
                self.indent_unit,
                self.tab_space_size,
                self.indent_style,
            );
            if !edits.is_empty() {
                has_violation = true;
            }
            edits
        } else {
            Vec::new()
        };

        if !has_violation {
            return Vec::new();
        }

        let mut issue = Issue::info(
            issue_codes::LINT_LT_002,
            "Indentation appears inconsistent.",
        )
        .with_statement(ctx.statement_index);

        let mut autofix_edits = indentation_autofix_edits(
            ctx.statement_sql(),
            &snapshots,
            self.indent_unit,
            self.tab_space_size,
            self.indent_style,
        );

        // Merge structural edits (e.g., adding indentation to content lines
        // under clause keywords). Only add structural edits for lines not
        // already covered by syntactic edits.
        if !structural_edits.is_empty() {
            let covered_starts: HashSet<usize> = autofix_edits.iter().map(|e| e.start).collect();
            for edit in structural_edits {
                if !covered_starts.contains(&edit.start) {
                    autofix_edits.push(edit);
                }
            }
        }

        let autofix_edits: Vec<_> = autofix_edits
            .into_iter()
            .map(|edit| {
                IssuePatchEdit::new(
                    ctx.span_from_statement_offset(edit.start, edit.end),
                    edit.replacement,
                )
            })
            .collect();

        if !autofix_edits.is_empty() {
            issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, autofix_edits);
        }

        vec![issue]
    }
}

fn first_line_is_indented(ctx: &LintContext) -> bool {
    let statement_start = ctx.statement_range.start;
    if statement_start == 0 {
        return false;
    }

    let line_start = ctx.sql[..statement_start]
        .rfind('\n')
        .map_or(0, |index| index + 1);
    let leading = &ctx.sql[line_start..statement_start];
    !leading.is_empty() && leading.chars().all(char::is_whitespace)
}

// ---------------------------------------------------------------------------
// Structural indent detection
// ---------------------------------------------------------------------------

/// Returns true if any line has indentation that violates structural
/// expectations. This catches cases where all indents are valid multiples
/// of indent_unit but are at the wrong depth for their SQL context.
///
/// The check focuses on "standalone clause keyword" patterns: when a clause
/// keyword that expects indented content (SELECT, FROM, WHERE, SET, etc.)
/// appears alone on a line, the content on the following line must be
/// indented by one indent_unit.
/// Returns autofix edits for structural indentation violations. When empty,
/// no structural violation was found.
fn structural_indent_edits(
    ctx: &LintContext,
    indent_unit: usize,
    tab_space_size: usize,
    indent_style: IndentStyle,
) -> Vec<Lt02AutofixEdit> {
    let sql = ctx.statement_sql();

    // Skip structural check for templated SQL. Template expansion can
    // produce indentation patterns that look structurally wrong but are
    // correct in the original source.
    if ctx.is_templated() {
        return Vec::new();
    }

    // Try to tokenize; if we cannot, fall back to no structural check.
    let tokens = tokenize_for_structural_check(sql, ctx);
    let tokens = match tokens.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return Vec::new(),
    };

    // Build per-line token info.
    let line_infos = build_line_token_infos(tokens);
    if line_infos.is_empty() {
        return Vec::new();
    }

    let actual_indents = actual_indent_map(sql, tab_space_size);
    let line_info_list = statement_line_infos(sql);
    let mut edits = Vec::new();

    // Check for structural violations: when a content-bearing clause keyword
    // is alone on its line, the following content line must be indented by
    // indent_unit more than the keyword line.
    let lines: Vec<usize> = line_infos.keys().copied().collect();
    for (i, &line) in lines.iter().enumerate() {
        let info = &line_infos[&line];
        if !info.is_standalone_content_clause {
            continue;
        }

        let keyword_indent = actual_indents.get(&line).copied().unwrap_or(0);
        let expected_content_indent = keyword_indent + indent_unit;

        // Find the next content line (skip blank lines).
        if let Some(&next_line) = lines.get(i + 1) {
            let next_info = &line_infos[&next_line];
            // Skip content lines that are clause keywords (they set their
            // own indent context) or SELECT modifiers (DISTINCT/ALL) which
            // belong with the preceding SELECT, not as indented content.
            if !next_info.starts_with_clause_keyword && !next_info.starts_with_select_modifier {
                let next_actual = actual_indents.get(&next_line).copied().unwrap_or(0);
                if next_actual != expected_content_indent {
                    if let Some(line_info) = line_info_list.get(next_line) {
                        let start = line_info.start;
                        let end = line_info.start + line_info.indent_end;
                        if end <= sql.len() && start <= end {
                            let replacement = make_indent(
                                expected_content_indent,
                                indent_unit,
                                tab_space_size,
                                indent_style,
                            );
                            edits.push(Lt02AutofixEdit {
                                start,
                                end,
                                replacement,
                            });
                        }
                    }
                }
            }
        }
    }

    // Check for comment-only trailing lines at deeper indentation than
    // any content line. E.g. `SELECT 1\n    -- foo\n        -- bar`
    // has comments indented beyond the content (indent 0), which is wrong.
    if let Some(&last_content_line) = line_infos
        .iter()
        .rev()
        .find(|(_, info)| !info.is_comment_only)
        .map(|(line, _)| line)
    {
        let last_content_indent = actual_indents.get(&last_content_line).copied().unwrap_or(0);
        // Check comment-only lines after the last content line.
        for (&line, info) in &line_infos {
            if line > last_content_line && info.is_comment_only {
                let comment_indent = actual_indents.get(&line).copied().unwrap_or(0);
                if comment_indent > last_content_indent {
                    if let Some(line_info) = line_info_list.get(line) {
                        let start = line_info.start;
                        let end = line_info.start + line_info.indent_end;
                        if end <= sql.len() && start <= end {
                            let replacement = make_indent(
                                last_content_indent,
                                indent_unit,
                                tab_space_size,
                                indent_style,
                            );
                            edits.push(Lt02AutofixEdit {
                                start,
                                end,
                                replacement,
                            });
                        }
                    }
                }
            }
        }
    }

    edits
}

/// Build the indent string for a given target width.
fn make_indent(
    width: usize,
    _indent_unit: usize,
    tab_space_size: usize,
    indent_style: IndentStyle,
) -> String {
    if width == 0 {
        return String::new();
    }
    match indent_style {
        IndentStyle::Spaces => " ".repeat(width),
        IndentStyle::Tabs => {
            let tab_width = tab_space_size.max(1);
            let tab_count = width.div_ceil(tab_width);
            "\t".repeat(tab_count)
        }
    }
}

/// Per-line summary of token structure.
struct LineTokenInfo {
    /// True if the line starts with a top-level clause keyword.
    starts_with_clause_keyword: bool,
    /// True if the line starts with a content-bearing clause keyword that is
    /// alone on the line. Content-bearing keywords are those whose content
    /// should be indented on the following line (SELECT, FROM, WHERE, SET,
    /// RETURNING, HAVING, LIMIT, QUALIFY, WINDOW, DECLARE). Keywords like
    /// WITH, CREATE, UNION are excluded because their "content" is other
    /// clause-level constructs, not indented content.
    is_standalone_content_clause: bool,
    /// True if the line contains only comment tokens.
    is_comment_only: bool,
    /// True if the line starts with a SELECT modifier (DISTINCT, ALL) that
    /// belongs with a preceding SELECT keyword rather than being content
    /// that should be indented.
    starts_with_select_modifier: bool,
}

/// Keywords whose content on the following line should be indented.
fn is_content_bearing_clause(kw: Keyword) -> bool {
    matches!(
        kw,
        Keyword::SELECT
            | Keyword::FROM
            | Keyword::WHERE
            | Keyword::SET
            | Keyword::RETURNING
            | Keyword::HAVING
            | Keyword::LIMIT
            | Keyword::QUALIFY
            | Keyword::WINDOW
            | Keyword::DECLARE
            | Keyword::VALUES
            | Keyword::UPDATE
    )
}

/// Build per-line token info from the token stream.
fn build_line_token_infos(tokens: &[StructuralToken]) -> BTreeMap<usize, LineTokenInfo> {
    let mut result: BTreeMap<usize, LineTokenInfo> = BTreeMap::new();

    // Group non-trivia tokens by line.
    let mut tokens_by_line: BTreeMap<usize, Vec<&StructuralToken>> = BTreeMap::new();
    for token in tokens {
        if is_whitespace_or_newline(&token.token) {
            continue;
        }
        tokens_by_line.entry(token.line).or_default().push(token);
    }

    // Track preceding keyword for GROUP BY / ORDER BY detection.
    let mut prev_keyword: Option<Keyword> = None;

    for (&line, line_tokens) in &tokens_by_line {
        let first = &line_tokens[0];
        let starts_with_clause = is_first_token_clause_keyword(first, prev_keyword);

        // Check if the first keyword is content-bearing.
        let first_is_content_bearing = match &first.token {
            Token::Word(w) => is_content_bearing_clause(w.keyword),
            _ => false,
        };

        // A clause keyword is "standalone" if all non-trivia tokens on the
        // line are clause keywords / modifiers / comments / semicolons.
        let is_standalone = starts_with_clause && first_is_content_bearing && {
            line_tokens.iter().all(|t| match &t.token {
                Token::Word(w) => {
                    is_clause_keyword_word(w.keyword)
                        || w.keyword == Keyword::NoKeyword && is_join_modifier(&w.value)
                }
                Token::SemiColon => true,
                _ => is_comment_token(&t.token),
            })
        };

        let comment_only = line_tokens.iter().all(|t| is_comment_token(&t.token));

        let starts_with_select_modifier = match &first.token {
            Token::Word(w) => matches!(w.keyword, Keyword::DISTINCT | Keyword::ALL),
            _ => false,
        };

        result.insert(
            line,
            LineTokenInfo {
                starts_with_clause_keyword: starts_with_clause,
                is_standalone_content_clause: is_standalone,
                is_comment_only: comment_only,
                starts_with_select_modifier,
            },
        );

        // Update prev_keyword from last keyword on this line.
        for t in line_tokens.iter().rev() {
            if let Token::Word(w) = &t.token {
                if w.keyword != Keyword::NoKeyword {
                    prev_keyword = Some(w.keyword);
                    break;
                }
            }
        }
    }

    result
}

fn is_first_token_clause_keyword(token: &StructuralToken, prev_keyword: Option<Keyword>) -> bool {
    match &token.token {
        Token::Word(w) => is_top_level_clause_keyword(w.keyword, prev_keyword),
        _ => false,
    }
}

fn is_comment_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_))
    )
}

/// Tokenize SQL for structural analysis. Falls back to statement-level
/// tokenization when document tokens are not available.
fn tokenize_for_structural_check(sql: &str, ctx: &LintContext) -> Option<Vec<StructuralToken>> {
    // Fall back to statement-level tokenization (document tokens use
    // 1-indexed lines which makes correlation harder; local tokenization
    // gives 0-indexed consistency).
    let dialect = ctx.dialect().to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let Ok(tokens) = tokenizer.tokenize_with_location() else {
        return None;
    };

    Some(
        tokens
            .into_iter()
            .filter_map(|t| {
                let line = t.span.start.line as usize;
                let col = t.span.start.column as usize;
                let offset = line_col_to_offset(sql, line, col)?;
                Some(StructuralToken {
                    token: t.token,
                    offset,
                    line: line.saturating_sub(1),
                })
            })
            .collect(),
    )
}

#[derive(Clone)]
struct StructuralToken {
    token: Token,
    #[allow(dead_code)]
    offset: usize,
    line: usize,
}

/// Returns true if the keyword starts a top-level SQL clause.
fn is_top_level_clause_keyword(kw: Keyword, _prev_keyword: Option<Keyword>) -> bool {
    is_clause_keyword_word(kw)
}

/// Core set of SQL clause keywords that establish a new indent level.
fn is_clause_keyword_word(kw: Keyword) -> bool {
    matches!(
        kw,
        Keyword::SELECT
            | Keyword::FROM
            | Keyword::WHERE
            | Keyword::SET
            | Keyword::UPDATE
            | Keyword::INSERT
            | Keyword::DELETE
            | Keyword::MERGE
            | Keyword::USING
            | Keyword::INTO
            | Keyword::VALUES
            | Keyword::RETURNING
            | Keyword::HAVING
            | Keyword::LIMIT
            | Keyword::WINDOW
            | Keyword::QUALIFY
            | Keyword::WITH
            | Keyword::BEGIN
            | Keyword::DECLARE
            | Keyword::IF
            | Keyword::RETURNS
            | Keyword::CREATE
            | Keyword::DROP
            | Keyword::ON
            | Keyword::JOIN
            | Keyword::INNER
            | Keyword::LEFT
            | Keyword::RIGHT
            | Keyword::FULL
            | Keyword::CROSS
            | Keyword::OUTER
    )
}

fn is_join_modifier(word: &str) -> bool {
    let upper = word.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "JOIN" | "INNER" | "LEFT" | "RIGHT" | "FULL" | "CROSS" | "OUTER" | "APPLY"
    )
}

fn is_whitespace_or_newline(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
    )
}

/// Build a map of line_index -> actual indent width from the SQL text.
fn actual_indent_map(sql: &str, tab_space_size: usize) -> BTreeMap<usize, usize> {
    let mut result = BTreeMap::new();
    for (idx, line) in sql.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = leading_indent_from_prefix(line, tab_space_size);
        result.insert(idx, indent.width);
    }
    result
}

// ---------------------------------------------------------------------------
// Original indent snapshot and autofix infrastructure
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct LeadingIndent {
    width: usize,
    space_count: usize,
    tab_count: usize,
    has_mixed_indent_chars: bool,
}

#[derive(Clone, Copy)]
struct LineIndentSnapshot {
    line_index: usize,
    indent: LeadingIndent,
}

struct StatementLineInfo {
    start: usize,
    indent_end: usize,
}

struct Lt02AutofixEdit {
    start: usize,
    end: usize,
    replacement: String,
}

fn line_indent_snapshots(ctx: &LintContext, tab_space_size: usize) -> Vec<LineIndentSnapshot> {
    if let Some(tokens) = tokenize_with_offsets_for_context(ctx) {
        let statement_start_line = offset_to_line(ctx.sql, ctx.statement_range.start);
        let mut first_token_by_line: BTreeMap<usize, usize> = BTreeMap::new();
        for token in &tokens {
            if token.start < ctx.statement_range.start || token.start >= ctx.statement_range.end {
                continue;
            }
            if is_whitespace_token(&token.token) {
                continue;
            }
            first_token_by_line
                .entry(token.start_line)
                .or_insert(token.start);
        }

        return first_token_by_line
            .into_iter()
            .map(|(line, token_start)| {
                let line_start = ctx.sql[..token_start]
                    .rfind('\n')
                    .map_or(0, |index| index + 1);
                let leading = &ctx.sql[line_start..token_start];
                LineIndentSnapshot {
                    line_index: line.saturating_sub(statement_start_line),
                    indent: leading_indent_from_prefix(leading, tab_space_size),
                }
            })
            .collect();
    }

    let sql = ctx.statement_sql();
    let Some(tokens) = tokenize_with_locations(sql, ctx.dialect()) else {
        return sql
            .lines()
            .enumerate()
            .filter_map(|(line_index, line)| {
                if line.trim().is_empty() {
                    return None;
                }
                Some(LineIndentSnapshot {
                    line_index,
                    indent: leading_indent(line, tab_space_size),
                })
            })
            .collect();
    };

    let mut first_token_by_line: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    for token in &tokens {
        if is_whitespace_token(&token.token) {
            continue;
        }
        let line = token.span.start.line as usize;
        let column = token.span.start.column as usize;
        first_token_by_line.entry(line).or_insert(column);
    }

    first_token_by_line
        .into_iter()
        .filter_map(|(line, column)| {
            let line_start = line_col_to_offset(sql, line, 1)?;
            let token_start = line_col_to_offset(sql, line, column)?;
            let leading = &sql[line_start..token_start];
            Some(LineIndentSnapshot {
                line_index: line.saturating_sub(1),
                indent: leading_indent_from_prefix(leading, tab_space_size),
            })
        })
        .collect()
}

#[derive(Clone)]
struct LocatedToken {
    token: Token,
    start: usize,
    start_line: usize,
}

fn tokenize_with_locations(sql: &str, dialect: Dialect) -> Option<Vec<TokenWithSpan>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    tokenizer.tokenize_with_location().ok()
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
                    token_with_span_offsets(ctx.sql, token).map(|(start, _end)| LocatedToken {
                        token: token.token.clone(),
                        start,
                        start_line: token.span.start.line as usize,
                    })
                })
                .collect::<Vec<_>>(),
        )
    })
}

fn is_whitespace_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Whitespace(Whitespace::Space | Whitespace::Tab | Whitespace::Newline)
    )
}

fn leading_indent(line: &str, tab_space_size: usize) -> LeadingIndent {
    leading_indent_from_prefix(line, tab_space_size)
}

fn leading_indent_from_prefix(prefix: &str, tab_space_size: usize) -> LeadingIndent {
    let mut width = 0usize;
    let mut space_count = 0usize;
    let mut tab_count = 0usize;

    for ch in prefix.chars() {
        match ch {
            ' ' => {
                space_count += 1;
                width += 1;
            }
            '\t' => {
                tab_count += 1;
                width += tab_space_size;
            }
            _ => break,
        }
    }

    LeadingIndent {
        width,
        space_count,
        tab_count,
        has_mixed_indent_chars: space_count > 0 && tab_count > 0,
    }
}

fn indentation_autofix_edits(
    statement_sql: &str,
    snapshots: &[LineIndentSnapshot],
    indent_unit: usize,
    tab_space_size: usize,
    indent_style: IndentStyle,
) -> Vec<Lt02AutofixEdit> {
    let line_infos = statement_line_infos(statement_sql);
    let mut edits = Vec::new();

    for snapshot in snapshots {
        let Some(line_info) = line_infos.get(snapshot.line_index) else {
            continue;
        };
        let start = line_info.start;
        let end = line_info.start + line_info.indent_end;
        if end > statement_sql.len() || start > end {
            continue;
        }

        let current_prefix = &statement_sql[start..end];
        let replacement = if snapshot.line_index == 0 {
            String::new()
        } else {
            normalized_indent_replacement(
                snapshot.indent.width,
                indent_unit,
                tab_space_size,
                indent_style,
            )
        };

        if replacement != current_prefix {
            edits.push(Lt02AutofixEdit {
                start,
                end,
                replacement,
            });
        }
    }

    edits
}

fn statement_line_infos(sql: &str) -> Vec<StatementLineInfo> {
    let mut infos = Vec::new();
    let mut line_start = 0usize;

    for segment in sql.split_inclusive('\n') {
        let line = segment.strip_suffix('\n').unwrap_or(segment);
        let indent_end = line
            .char_indices()
            .find_map(|(index, ch)| {
                if matches!(ch, ' ' | '\t') {
                    None
                } else {
                    Some(index)
                }
            })
            .unwrap_or(line.len());
        infos.push(StatementLineInfo {
            start: line_start,
            indent_end,
        });
        line_start += segment.len();
    }

    infos
}

fn normalized_indent_replacement(
    width: usize,
    indent_unit: usize,
    tab_space_size: usize,
    indent_style: IndentStyle,
) -> String {
    if width == 0 {
        return String::new();
    }

    let rounded = rounded_indent_width(width, indent_unit.max(1));
    if rounded == 0 {
        return String::new();
    }

    match indent_style {
        IndentStyle::Spaces => " ".repeat(rounded),
        IndentStyle::Tabs => {
            let tab_width = tab_space_size.max(1);
            let tab_count = rounded.div_ceil(tab_width).max(1);
            "\t".repeat(tab_count)
        }
    }
}

fn rounded_indent_width(width: usize, indent_unit: usize) -> usize {
    if width == 0 || indent_unit == 0 {
        return width;
    }

    if width.is_multiple_of(indent_unit) {
        return width;
    }

    let down = (width / indent_unit) * indent_unit;
    let up = down + indent_unit;
    if down == 0 {
        up
    } else if width - down <= up - width {
        down
    } else {
        up
    }
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

fn offset_to_line(sql: &str, offset: usize) -> usize {
    1 + sql[..offset.min(sql.len())]
        .chars()
        .filter(|ch| *ch == '\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linter::config::LintConfig;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        run_with_config(sql, LintConfig::default())
    }

    fn run_with_config(sql: &str, config: LintConfig) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = LayoutIndent::from_config(&config);
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
    fn flags_odd_indent_width() {
        let issues = run("SELECT a\n   , b\nFROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn odd_indent_width_emits_safe_autofix() {
        let sql = "SELECT a\n   , b\nFROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a\n    , b\nFROM t");
    }

    #[test]
    fn flags_first_line_indentation() {
        let issues = run("   SELECT 1");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn first_line_indentation_emits_safe_autofix_when_editable() {
        let sql = "   SELECT 1";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT 1");
    }

    #[test]
    fn does_not_flag_even_indent_width() {
        assert!(run("SELECT a\n    , b\nFROM t").is_empty());
    }

    #[test]
    fn flags_mixed_tab_and_space_indentation() {
        let issues = run("SELECT a\n \t, b\nFROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn tab_space_size_config_is_applied_for_tab_indentation_width() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "layout.indent".to_string(),
                serde_json::json!({"tab_space_size": 2, "indent_unit": "tab"}),
            )]),
        };
        let issues = run_with_config("SELECT a\n\t, b\nFROM t", config);
        assert!(issues.is_empty());
    }

    #[test]
    fn tab_indent_unit_disallows_space_indent() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "layout.indent".to_string(),
                serde_json::json!({"indent_unit": "tab"}),
            )]),
        };
        let issues = run_with_config("SELECT a\n    , b\nFROM t", config);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn tab_indent_style_emits_tab_autofix() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "layout.indent".to_string(),
                serde_json::json!({"indent_unit": "tab"}),
            )]),
        };
        let sql = "SELECT a\n    , b\nFROM t";
        let issues = run_with_config(sql, config);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT a\n\t, b\nFROM t");
    }

    #[test]
    fn indentation_section_options_are_supported() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "indentation".to_string(),
                serde_json::json!({"indent_unit": "tab", "tab_space_size": 2}),
            )]),
        };
        let issues = run_with_config("SELECT a\n\t, b\nFROM t", config);
        assert!(issues.is_empty());
    }

    #[test]
    fn indentation_on_comment_line_is_checked() {
        let issues = run("SELECT 1\n   -- comment\nFROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn first_line_indent_outside_statement_range_is_report_only() {
        let sql = "   SELECT 1";
        let statements = parse_sql(sql).expect("parse");
        let rule = LayoutIndent::default();
        let issues = rule.check(
            &statements[0],
            &LintContext {
                sql,
                statement_range: 3..sql.len(),
                statement_index: 0,
            },
        );
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "non-editable first-line prefix should remain report-only"
        );
    }

    // Structural indentation tests.

    #[test]
    fn flags_clause_content_not_indented_under_update() {
        // UPDATE\nfoo\nSET\nupdated = now()\nWHERE\n    bar = '';
        // "foo" should be indented under UPDATE, "updated" under SET.
        let issues = run("UPDATE\nfoo\nSET\nupdated = now()\nWHERE\n    bar = '';");
        assert_eq!(issues.len(), 1, "should flag unindented clause contents");
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn flags_unindented_from_content() {
        // FROM\nmy_tbl should flag because my_tbl is not indented.
        let issues = run("SELECT\n    a,\n    b\nFROM\nmy_tbl");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn accepts_properly_indented_clauses() {
        // All clause contents properly indented.
        let issues = run("SELECT\n    a,\n    b\nFROM\n    my_tbl\nWHERE\n    a = 1");
        assert!(issues.is_empty(), "properly indented SQL should not flag");
    }

    #[test]
    fn flags_trailing_comment_wrong_indent() {
        // Trailing comments at deepening indent levels after content at
        // indent 0. Both `-- foo` (indent 4) and `-- bar` (indent 8) are
        // deeper than `SELECT 1` (indent 0).
        let issues = run("SELECT 1\n    -- foo\n        -- bar");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_LT_002);
    }

    #[test]
    fn accepts_properly_indented_trailing_comment() {
        // Comment at same indent as the content line before it is fine.
        let issues = run("SELECT\n    a\n    -- explains next col\n    , b\nFROM t");
        assert!(issues.is_empty());
    }

    // Structural autofix tests.

    #[test]
    fn structural_autofix_indents_content_under_clause_keyword() {
        // RETURNING\nupdated should fix to RETURNING\n    updated
        let sql = "INSERT INTO foo (updated)\nVALUES (now())\nRETURNING\nupdated;";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(
            fixed,
            "INSERT INTO foo (updated)\nVALUES (now())\nRETURNING\n    updated;"
        );
    }

    #[test]
    fn structural_autofix_indents_update_content() {
        // UPDATE\nfoo -> UPDATE\n    foo
        let sql = "UPDATE\nfoo\nSET\nupdated = now()\nWHERE\n    bar = ''";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(
            fixed,
            "UPDATE\n    foo\nSET\n    updated = now()\nWHERE\n    bar = ''"
        );
    }

    #[test]
    fn structural_autofix_indents_from_content() {
        let sql = "SELECT\n    a,\n    b\nFROM\nmy_tbl";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "SELECT\n    a,\n    b\nFROM\n    my_tbl");
    }

    #[test]
    fn structural_autofix_fixes_trailing_comment_indent() {
        let sql = "SELECT 1\n    -- foo\n        -- bar";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        // Both comments should be at indent 0 (same as content line).
        assert_eq!(fixed, "SELECT 1\n-- foo\n-- bar");
    }
}
