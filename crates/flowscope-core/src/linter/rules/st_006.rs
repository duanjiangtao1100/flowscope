//! LINT_ST_006: Structure column order.
//!
//! SQLFluff ST06 parity: prefer simple column references before complex
//! expressions in SELECT projection lists.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{Expr, SelectItem, Statement};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

use super::semantic_helpers::visit_selects_in_statement;

pub struct StructureColumnOrder;

impl LintRule for StructureColumnOrder {
    fn code(&self) -> &'static str {
        issue_codes::LINT_ST_006
    }

    fn name(&self) -> &'static str {
        "Structure column order"
    }

    fn description(&self) -> &'static str {
        "Select wildcards then simple targets before calculations and aggregates."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut first_simple_indexes = Vec::new();
        visit_selects_in_statement(statement, &mut |select| {
            first_simple_indexes.push(select.projection.iter().position(is_simple_projection_item));
        });

        let violations = first_simple_indexes
            .iter()
            .filter_map(|index| *index)
            .filter(|index| *index > 0)
            .count();

        let mut autofix_candidates =
            st006_autofix_candidates_for_context(ctx, &first_simple_indexes);
        autofix_candidates.sort_by_key(|candidate| candidate.span.start);
        let candidates_align = autofix_candidates.len() == violations;

        (0..violations)
            .map(|index| {
                let mut issue = Issue::info(
                    issue_codes::LINT_ST_006,
                    "Prefer simple columns before complex expressions in SELECT.",
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
struct SelectProjectionSegment {
    item_spans: Vec<Span>,
}

#[derive(Clone, Debug)]
struct St006AutofixCandidate {
    span: Span,
    edits: Vec<IssuePatchEdit>,
}

fn st006_autofix_candidates_for_context(
    ctx: &LintContext,
    first_simple_indexes: &[Option<usize>],
) -> Vec<St006AutofixCandidate> {
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

    let tokens = if let Some(tokens) = from_document_tokens {
        tokens
    } else {
        let Some(tokens) = tokenize_with_spans(ctx.statement_sql(), ctx.dialect()) else {
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
    };

    let segments = select_projection_segments(&tokens);
    if segments.len() != first_simple_indexes.len() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    for (segment, first_simple_idx) in segments.iter().zip(first_simple_indexes.iter()) {
        let Some(first_simple_idx) = *first_simple_idx else {
            continue;
        };
        if first_simple_idx == 0 {
            continue;
        }

        let Some(candidate) =
            projection_reorder_candidate(ctx.sql, &tokens, segment, first_simple_idx)
        else {
            continue;
        };
        candidates.push(candidate);
    }

    candidates
}

fn select_projection_segments(tokens: &[PositionedToken]) -> Vec<SelectProjectionSegment> {
    let significant_positions: Vec<usize> = tokens
        .iter()
        .enumerate()
        .filter_map(|(index, token)| (!is_trivia(&token.token)).then_some(index))
        .collect();
    if significant_positions.is_empty() {
        return Vec::new();
    }

    let mut depths = vec![0usize; significant_positions.len()];
    let mut depth = 0usize;
    for (position, token_index) in significant_positions.iter().copied().enumerate() {
        depths[position] = depth;
        match tokens[token_index].token {
            Token::LParen => depth += 1,
            Token::RParen => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    let mut segments = Vec::new();
    for position in 0..significant_positions.len() {
        let token = &tokens[significant_positions[position]].token;
        if !token_word_equals(token, "SELECT") {
            continue;
        }

        let base_depth = depths[position];
        let Some(projection_start) = projection_start_after_select(
            tokens,
            &significant_positions,
            &depths,
            position + 1,
            base_depth,
        ) else {
            continue;
        };
        let Some(from_position) = from_position_for_select(
            tokens,
            &significant_positions,
            &depths,
            projection_start,
            base_depth,
        ) else {
            continue;
        };
        if from_position <= projection_start {
            continue;
        }

        let item_spans = projection_item_spans(
            tokens,
            &significant_positions,
            &depths,
            projection_start,
            from_position,
            base_depth,
        );
        if item_spans.is_empty() {
            continue;
        }

        segments.push(SelectProjectionSegment { item_spans });
    }

    segments
}

fn projection_start_after_select(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    depths: &[usize],
    mut position: usize,
    base_depth: usize,
) -> Option<usize> {
    while position < significant_positions.len() {
        if depths[position] != base_depth {
            return Some(position);
        }

        let token = &tokens[significant_positions[position]].token;
        if token_word_equals(token, "DISTINCT")
            || token_word_equals(token, "ALL")
            || token_word_equals(token, "DISTINCTROW")
        {
            position += 1;
            continue;
        }
        return Some(position);
    }

    None
}

fn from_position_for_select(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    depths: &[usize],
    start_position: usize,
    base_depth: usize,
) -> Option<usize> {
    (start_position..significant_positions.len()).find(|&position| {
        depths[position] == base_depth
            && token_word_equals(&tokens[significant_positions[position]].token, "FROM")
    })
}

fn projection_item_spans(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    depths: &[usize],
    start_position: usize,
    from_position: usize,
    base_depth: usize,
) -> Vec<Span> {
    if start_position >= from_position {
        return Vec::new();
    }

    let mut spans = Vec::new();
    let mut item_start = start_position;

    for position in start_position..from_position {
        let token = &tokens[significant_positions[position]].token;
        if depths[position] == base_depth && matches!(token, Token::Comma) {
            if item_start < position {
                if let Some(span) =
                    span_from_positions(tokens, significant_positions, item_start, position - 1)
                {
                    spans.push(span);
                }
            }
            item_start = position + 1;
        }
    }

    if item_start < from_position {
        if let Some(span) =
            span_from_positions(tokens, significant_positions, item_start, from_position - 1)
        {
            spans.push(span);
        }
    }

    spans
}

fn span_from_positions(
    tokens: &[PositionedToken],
    significant_positions: &[usize],
    start_position: usize,
    end_position: usize,
) -> Option<Span> {
    if end_position < start_position {
        return None;
    }

    let start = tokens[*significant_positions.get(start_position)?].start;
    let end = tokens[*significant_positions.get(end_position)?].end;
    (start < end).then_some(Span::new(start, end))
}

fn projection_reorder_candidate(
    sql: &str,
    tokens: &[PositionedToken],
    segment: &SelectProjectionSegment,
    first_simple_idx: usize,
) -> Option<St006AutofixCandidate> {
    if first_simple_idx >= segment.item_spans.len() {
        return None;
    }

    let replace_span = Span::new(
        segment.item_spans.first()?.start,
        segment.item_spans.last()?.end,
    );
    if replace_span.start >= replace_span.end || replace_span.end > sql.len() {
        return None;
    }
    if segment_contains_comment(tokens, replace_span) {
        return None;
    }

    let mut item_texts = Vec::with_capacity(segment.item_spans.len());
    for span in &segment.item_spans {
        if span.start >= span.end || span.end > sql.len() {
            return None;
        }
        let text = sql[span.start..span.end].trim();
        if text.is_empty() || text.contains('\n') || text.contains('\r') {
            return None;
        }
        item_texts.push(text.to_string());
    }

    let mut reordered = Vec::with_capacity(item_texts.len());
    reordered.extend(item_texts[first_simple_idx..].iter().cloned());
    reordered.extend(item_texts[..first_simple_idx].iter().cloned());
    let replacement = reordered.join(", ");
    if replacement.is_empty() || replacement == sql[replace_span.start..replace_span.end].trim() {
        return None;
    }

    Some(St006AutofixCandidate {
        span: replace_span,
        edits: vec![IssuePatchEdit::new(replace_span, replacement)],
    })
}

fn segment_contains_comment(tokens: &[PositionedToken], span: Span) -> bool {
    tokens
        .iter()
        .any(|token| token.start >= span.start && token.end <= span.end && is_comment(&token.token))
}

fn is_simple_projection_item(item: &SelectItem) -> bool {
    match item {
        SelectItem::UnnamedExpr(Expr::Identifier(_))
        | SelectItem::UnnamedExpr(Expr::CompoundIdentifier(_)) => true,
        SelectItem::ExprWithAlias { expr, .. } => {
            matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
        }
        _ => false,
    }
}

fn tokenize_with_spans(sql: &str, dialect: Dialect) -> Option<Vec<TokenWithSpan>> {
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
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = StructureColumnOrder;
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

    // --- Edge cases adopted from sqlfluff ST06 ---

    #[test]
    fn flags_when_complex_projection_precedes_first_simple_target() {
        let issues = run("SELECT a + 1, a FROM t");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_ST_006);
    }

    #[test]
    fn does_not_flag_when_simple_target_starts_projection() {
        let issues = run("SELECT a, a + 1 FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn does_not_flag_when_simple_target_appears_again_after_complex() {
        let issues = run("SELECT a, a + 1, b FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn does_not_flag_when_alias_wraps_simple_identifier() {
        let issues = run("SELECT a AS first_a, b FROM t");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_in_nested_select_scopes() {
        let issues = run("SELECT * FROM (SELECT a + 1, a FROM t) AS sub");
        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn emits_safe_autofix_for_simple_projection_reorder() {
        let sql = "SELECT a + 1, a FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected ST006 core autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        assert_eq!(autofix.edits[0].replacement, "a, a + 1");
    }

    #[test]
    fn comment_in_projection_blocks_safe_autofix_metadata() {
        let sql = "SELECT a + 1 /*keep*/, a FROM t";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert!(
            issues[0].autofix.is_none(),
            "comment-bearing projection should not receive ST006 safe patch metadata"
        );
    }
}
