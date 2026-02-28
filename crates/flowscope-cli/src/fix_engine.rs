//! Deterministic patch planning helpers for lint fixes.
//!
//! This module intentionally keeps the API small and explicit:
//! - `plan_fixes()` selects compatible fixes and records blocked reasons.
//! - `apply_edits()` applies byte-range replacements end-to-start.
//! - protected range helpers mark SQL comments/string literals and template tags.

use flowscope_core::{issue_codes, Dialect};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

/// How safe it is to apply a fix automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FixApplicability {
    Safe,
    Unsafe,
    DisplayOnly,
}

/// A single text replacement in byte offsets `[start_byte, end_byte)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edit {
    pub start_byte: usize,
    pub end_byte: usize,
    pub replacement: String,
}

impl Edit {
    #[must_use]
    pub fn replace(start_byte: usize, end_byte: usize, replacement: impl Into<String>) -> Self {
        Self {
            start_byte,
            end_byte,
            replacement: replacement.into(),
        }
    }
}

/// A fix proposal, potentially containing multiple edits.
///
/// `priority` is sorted ascending, so lower numbers win first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    pub edits: Vec<Edit>,
    pub applicability: FixApplicability,
    pub isolation_group: Option<String>,
    pub rule_code: String,
    pub priority: i32,
}

impl Fix {
    #[must_use]
    pub fn new(
        rule_code: impl Into<String>,
        applicability: FixApplicability,
        edits: Vec<Edit>,
    ) -> Self {
        Self {
            edits,
            applicability,
            isolation_group: None,
            rule_code: rule_code.into(),
            priority: 0,
        }
    }

    #[must_use]
    pub fn first_start_byte(&self) -> usize {
        self.edits
            .iter()
            .map(|edit| edit.start_byte)
            .min()
            .unwrap_or(usize::MAX)
    }
}

/// Why a range is protected from automatic edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtectedRangeKind {
    SqlComment,
    SqlStringLiteral,
    TemplateTag,
}

/// Byte range that should not be changed by automatic fix application.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtectedRange {
    pub start_byte: usize,
    pub end_byte: usize,
    pub kind: ProtectedRangeKind,
}

impl ProtectedRange {
    #[must_use]
    pub fn new(start_byte: usize, end_byte: usize, kind: ProtectedRangeKind) -> Self {
        Self {
            start_byte,
            end_byte,
            kind,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedReason {
    ApplicabilityNotAllowed {
        applicability: FixApplicability,
    },
    InvalidEditRange {
        edit_index: usize,
        start_byte: usize,
        end_byte: usize,
    },
    InternalEditOverlap {
        left_edit: usize,
        right_edit: usize,
    },
    OverlapWithSelectedFix {
        selected_rule_code: String,
    },
    IsolationGroupConflict {
        isolation_group: String,
        selected_rule_code: String,
    },
    TouchesProtectedRange {
        kind: ProtectedRangeKind,
        start_byte: usize,
        end_byte: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedFix {
    pub fix: Fix,
    pub reasons: Vec<BlockedReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlanResult {
    pub accepted: Vec<Fix>,
    pub blocked: Vec<BlockedFix>,
}

impl PlanResult {
    #[must_use]
    pub fn accepted_edits(&self) -> Vec<Edit> {
        let mut edits: Vec<Edit> = self
            .accepted
            .iter()
            .flat_map(|fix| fix.edits.iter().cloned())
            .collect();
        sort_edits_deterministically(&mut edits);
        edits
    }

    #[must_use]
    pub fn apply(&self, source: &str) -> String {
        apply_edits(source, &self.accepted_edits())
    }
}

/// Derive protected ranges from SQL comments/string literals and template tags.
#[must_use]
pub fn derive_protected_ranges(sql: &str, dialect: Dialect) -> Vec<ProtectedRange> {
    let mut ranges = protected_ranges_from_tokenizer(sql, dialect);
    ranges.extend(protected_ranges_from_templates(sql));
    normalize_protected_ranges(ranges)
}

/// Derive protected ranges by tokenizing SQL and collecting comment + string tokens.
#[must_use]
pub fn protected_ranges_from_tokenizer(sql: &str, dialect: Dialect) -> Vec<ProtectedRange> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let Ok(tokens) = tokenizer.tokenize_with_location() else {
        return Vec::new();
    };

    let mut ranges = Vec::new();
    for token in tokens {
        let kind = match &token.token {
            Token::Whitespace(
                Whitespace::SingleLineComment { .. } | Whitespace::MultiLineComment(_),
            ) => Some(ProtectedRangeKind::SqlComment),
            token if is_string_literal_token(token) => Some(ProtectedRangeKind::SqlStringLiteral),
            _ => None,
        };

        let Some(kind) = kind else {
            continue;
        };
        let Some((start_byte, end_byte)) = token_with_span_offsets(sql, &token) else {
            continue;
        };
        if start_byte < end_byte {
            // Exclude trailing newlines from single-line comment protection.
            // The newline is a line separator, not comment content — other rules
            // may need to adjust it when rearranging lines.
            let mut adjusted_end = end_byte;
            if matches!(
                &token.token,
                Token::Whitespace(Whitespace::SingleLineComment { .. })
            ) {
                while adjusted_end > start_byte
                    && matches!(sql.as_bytes().get(adjusted_end - 1), Some(b'\n' | b'\r'))
                {
                    adjusted_end -= 1;
                }
            }
            if start_byte < adjusted_end {
                ranges.push(ProtectedRange::new(start_byte, adjusted_end, kind));
            }
        }
    }

    normalize_protected_ranges(ranges)
}

/// Derive protected ranges for Jinja-style templated spans.
///
/// This scanner handles:
/// - `{{ ... }}`, `{% ... %}`, `{# ... #}`
/// - trim markers (`{{-`, `-}}`, `{%-`, `-%}`, `{#-`, `-#}`)
/// - quoted strings inside `{{ ... }}` and `{% ... %}` so embedded `}}`/`%}`
///   inside string literals do not terminate a tag early.
#[must_use]
pub fn protected_ranges_from_templates(sql: &str) -> Vec<ProtectedRange> {
    let bytes = sql.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0usize;

    while index + 1 < bytes.len() {
        let Some(open_kind) = template_open_kind(bytes, index) else {
            index += 1;
            continue;
        };

        let close_lead = template_close_lead(open_kind);
        let start = index;
        let mut cursor = index + 2;

        if cursor < bytes.len() && bytes[cursor] == b'-' {
            cursor += 1;
        }

        let mut in_single_quote = false;
        let mut in_double_quote = false;
        let mut escaped = false;
        let mut end = None;

        while cursor < bytes.len() {
            let byte = bytes[cursor];

            if in_single_quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'\'' {
                    in_single_quote = false;
                }
                cursor += 1;
                continue;
            }

            if in_double_quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_double_quote = false;
                }
                cursor += 1;
                continue;
            }

            // Jinja comments are opaque; for expression and statement tags we
            // preserve quote state to avoid prematurely closing on `}}`/`%}`
            // in quoted content.
            if open_kind != b'#' {
                if byte == b'\'' {
                    in_single_quote = true;
                    cursor += 1;
                    continue;
                }
                if byte == b'"' {
                    in_double_quote = true;
                    cursor += 1;
                    continue;
                }
            }

            if is_template_close(bytes, cursor, close_lead) {
                end = Some(cursor + 2);
                break;
            }
            if is_template_trimmed_close(bytes, cursor, close_lead) {
                end = Some(cursor + 3);
                break;
            }

            cursor += 1;
        }

        let end = end.unwrap_or(bytes.len());
        ranges.push(ProtectedRange::new(
            start,
            end,
            ProtectedRangeKind::TemplateTag,
        ));
        index = end;
    }

    normalize_protected_ranges(ranges)
}

/// Plan fixes deterministically and collect blocked reasons.
///
/// Order is deterministic by: `priority`, first edit start, `rule_code`, then
/// additional stable tie-breakers.
///
/// If `allowed_applicability` is empty, all applicability classes are allowed.
#[must_use]
pub fn plan_fixes(
    source: &str,
    mut fixes: Vec<Fix>,
    allowed_applicability: &[FixApplicability],
    protected_ranges: &[ProtectedRange],
) -> PlanResult {
    sort_fixes_deterministically(&mut fixes);

    let allowed: HashSet<FixApplicability> = allowed_applicability.iter().copied().collect();
    let allow_all = allowed.is_empty();
    let normalized_protected_ranges = normalize_protected_ranges(protected_ranges.to_vec());

    let mut accepted = Vec::new();
    let mut blocked = Vec::new();
    let mut selected_edits: Vec<(Edit, String)> = Vec::new();
    let mut selected_groups: HashMap<String, String> = HashMap::new();

    for fix in fixes {
        let mut reasons = Vec::new();

        if !allow_all && !allowed.contains(&fix.applicability) {
            reasons.push(BlockedReason::ApplicabilityNotAllowed {
                applicability: fix.applicability,
            });
        }

        for (edit_index, edit) in fix.edits.iter().enumerate() {
            if !is_edit_range_valid_for_source(source, edit) {
                reasons.push(BlockedReason::InvalidEditRange {
                    edit_index,
                    start_byte: edit.start_byte,
                    end_byte: edit.end_byte,
                });
            }
        }

        for (left_edit, right_edit) in overlapping_edit_pairs(&fix.edits) {
            reasons.push(BlockedReason::InternalEditOverlap {
                left_edit,
                right_edit,
            });
        }

        for touched in touched_protected_ranges(&fix.edits, &normalized_protected_ranges) {
            if touched.kind == ProtectedRangeKind::TemplateTag
                && template_edits_allowed(&fix.rule_code)
            {
                continue;
            }
            reasons.push(BlockedReason::TouchesProtectedRange {
                kind: touched.kind,
                start_byte: touched.start_byte,
                end_byte: touched.end_byte,
            });
        }

        if let Some(group) = normalized_isolation_group(&fix.isolation_group) {
            if let Some(selected_rule_code) = selected_groups.get(group) {
                reasons.push(BlockedReason::IsolationGroupConflict {
                    isolation_group: group.to_string(),
                    selected_rule_code: selected_rule_code.clone(),
                });
            }
        }

        let mut overlapping_rules = BTreeSet::new();
        for edit in &fix.edits {
            for (selected_edit, selected_rule_code) in &selected_edits {
                if edits_overlap(edit, selected_edit) {
                    overlapping_rules.insert(selected_rule_code.clone());
                }
            }
        }
        for selected_rule_code in overlapping_rules {
            reasons.push(BlockedReason::OverlapWithSelectedFix { selected_rule_code });
        }

        dedup_reasons(&mut reasons);
        if reasons.is_empty() {
            if let Some(group) = normalized_isolation_group(&fix.isolation_group) {
                selected_groups.insert(group.to_string(), fix.rule_code.clone());
            }
            for edit in &fix.edits {
                selected_edits.push((edit.clone(), fix.rule_code.clone()));
            }
            accepted.push(fix);
        } else {
            blocked.push(BlockedFix { fix, reasons });
        }
    }

    PlanResult { accepted, blocked }
}

/// Sort fixes in deterministic planning order.
pub fn sort_fixes_deterministically(fixes: &mut [Fix]) {
    fixes.sort_by(compare_fixes_for_planning);
}

/// Sort edits in deterministic order.
pub fn sort_edits_deterministically(edits: &mut [Edit]) {
    edits.sort_by(compare_edits);
}

/// Return overlapping edit index pairs `(left, right)`.
#[must_use]
pub fn overlapping_edit_pairs(edits: &[Edit]) -> Vec<(usize, usize)> {
    let mut overlaps = Vec::new();
    for left in 0..edits.len() {
        for right in (left + 1)..edits.len() {
            if edits_overlap(&edits[left], &edits[right]) {
                overlaps.push((left, right));
            }
        }
    }
    overlaps
}

/// Return protected ranges touched by the provided edits.
#[must_use]
pub fn touched_protected_ranges(
    edits: &[Edit],
    protected_ranges: &[ProtectedRange],
) -> Vec<ProtectedRange> {
    let mut touched = Vec::new();
    for protected in protected_ranges {
        if edits
            .iter()
            .any(|edit| edit_touches_protected_range(edit, protected))
        {
            touched.push(protected.clone());
        }
    }
    normalize_protected_ranges(touched)
}

/// Apply a set of fixes to the source.
#[must_use]
pub fn apply_fixes(source: &str, fixes: &[Fix]) -> String {
    let edits: Vec<Edit> = fixes
        .iter()
        .flat_map(|fix| fix.edits.iter().cloned())
        .collect();
    apply_edits(source, &edits)
}

/// Apply edits to source by processing from end to start.
#[must_use]
pub fn apply_edits(source: &str, edits: &[Edit]) -> String {
    if edits.is_empty() {
        return source.to_string();
    }

    let mut ordered = edits.to_vec();
    sort_edits_deterministically(&mut ordered);

    let mut out = source.to_string();
    for edit in ordered.into_iter().rev() {
        if !is_edit_range_valid_for_source(&out, &edit) {
            continue;
        }
        out.replace_range(edit.start_byte..edit.end_byte, &edit.replacement);
    }

    out
}

fn compare_fixes_for_planning(left: &Fix, right: &Fix) -> Ordering {
    left.priority
        .cmp(&right.priority)
        .then_with(|| left.first_start_byte().cmp(&right.first_start_byte()))
        .then_with(|| left.rule_code.cmp(&right.rule_code))
        .then_with(|| {
            applicability_rank(left.applicability).cmp(&applicability_rank(right.applicability))
        })
        .then_with(|| {
            left.isolation_group
                .as_deref()
                .cmp(&right.isolation_group.as_deref())
        })
        .then_with(|| compare_edit_sets(&left.edits, &right.edits))
}

fn compare_edits(left: &Edit, right: &Edit) -> Ordering {
    left.start_byte
        .cmp(&right.start_byte)
        .then_with(|| left.end_byte.cmp(&right.end_byte))
        .then_with(|| left.replacement.cmp(&right.replacement))
}

fn compare_edit_sets(left: &[Edit], right: &[Edit]) -> Ordering {
    let mut left_sorted = left.to_vec();
    let mut right_sorted = right.to_vec();
    sort_edits_deterministically(&mut left_sorted);
    sort_edits_deterministically(&mut right_sorted);

    for (left_edit, right_edit) in left_sorted.iter().zip(right_sorted.iter()) {
        let ordering = compare_edits(left_edit, right_edit);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left_sorted.len().cmp(&right_sorted.len())
}

fn applicability_rank(applicability: FixApplicability) -> u8 {
    match applicability {
        FixApplicability::Safe => 0,
        FixApplicability::Unsafe => 1,
        FixApplicability::DisplayOnly => 2,
    }
}

fn dedup_reasons(reasons: &mut Vec<BlockedReason>) {
    let mut unique = Vec::with_capacity(reasons.len());
    for reason in reasons.drain(..) {
        if !unique.contains(&reason) {
            unique.push(reason);
        }
    }
    *reasons = unique;
}

fn normalized_isolation_group(group: &Option<String>) -> Option<&str> {
    group
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn normalize_protected_ranges(mut ranges: Vec<ProtectedRange>) -> Vec<ProtectedRange> {
    ranges.retain(|range| range.start_byte < range.end_byte);
    ranges.sort_by(|left, right| {
        left.start_byte
            .cmp(&right.start_byte)
            .then_with(|| left.end_byte.cmp(&right.end_byte))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    ranges.dedup();
    ranges
}

fn template_edits_allowed(rule_code: &str) -> bool {
    rule_code.eq_ignore_ascii_case(issue_codes::LINT_LT_005)
}

fn is_edit_range_valid_for_source(source: &str, edit: &Edit) -> bool {
    edit.start_byte <= edit.end_byte
        && edit.end_byte <= source.len()
        && source.is_char_boundary(edit.start_byte)
        && source.is_char_boundary(edit.end_byte)
}

fn edits_overlap(left: &Edit, right: &Edit) -> bool {
    let left_insert = left.start_byte == left.end_byte;
    let right_insert = right.start_byte == right.end_byte;

    if left_insert && right_insert {
        return left.start_byte == right.start_byte;
    }
    if left_insert {
        return left.start_byte >= right.start_byte && left.start_byte < right.end_byte;
    }
    if right_insert {
        return right.start_byte >= left.start_byte && right.start_byte < left.end_byte;
    }

    left.start_byte < right.end_byte && right.start_byte < left.end_byte
}

fn edit_touches_protected_range(edit: &Edit, protected: &ProtectedRange) -> bool {
    if edit.start_byte == edit.end_byte {
        return edit.start_byte >= protected.start_byte && edit.start_byte < protected.end_byte;
    }
    edit.start_byte < protected.end_byte && edit.end_byte > protected.start_byte
}

fn is_string_literal_token(token: &Token) -> bool {
    matches!(
        token,
        Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedByteStringLiteral(_)
            | Token::TripleDoubleQuotedByteStringLiteral(_)
            | Token::SingleQuotedRawStringLiteral(_)
            | Token::DoubleQuotedRawStringLiteral(_)
            | Token::TripleSingleQuotedRawStringLiteral(_)
            | Token::TripleDoubleQuotedRawStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_)
    )
}

fn token_with_span_offsets(sql: &str, token: &TokenWithSpan) -> Option<(usize, usize)> {
    let start_byte = line_col_to_offset(
        sql,
        token.span.start.line as usize,
        token.span.start.column as usize,
    )?;
    let end_byte = line_col_to_offset(
        sql,
        token.span.end.line as usize,
        token.span.end.column as usize,
    )?;
    Some((start_byte, end_byte))
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

fn template_open_kind(bytes: &[u8], index: usize) -> Option<u8> {
    if index + 1 >= bytes.len() || bytes[index] != b'{' {
        return None;
    }

    match bytes[index + 1] {
        b'{' | b'%' | b'#' => Some(bytes[index + 1]),
        _ => None,
    }
}

fn template_close_lead(open_kind: u8) -> u8 {
    match open_kind {
        b'{' => b'}',
        b'%' => b'%',
        b'#' => b'#',
        _ => unreachable!("unsupported template open marker"),
    }
}

fn is_template_close(bytes: &[u8], index: usize, close_lead: u8) -> bool {
    index + 1 < bytes.len() && bytes[index] == close_lead && bytes[index + 1] == b'}'
}

fn is_template_trimmed_close(bytes: &[u8], index: usize, close_lead: u8) -> bool {
    index + 2 < bytes.len()
        && bytes[index] == b'-'
        && bytes[index + 1] == close_lead
        && bytes[index + 2] == b'}'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_fix(
        rule_code: &str,
        priority: i32,
        isolation_group: Option<&str>,
        start_byte: usize,
        end_byte: usize,
        replacement: &str,
    ) -> Fix {
        Fix {
            edits: vec![Edit::replace(start_byte, end_byte, replacement)],
            applicability: FixApplicability::Safe,
            isolation_group: isolation_group.map(ToOwned::to_owned),
            rule_code: rule_code.to_string(),
            priority,
        }
    }

    #[test]
    fn planner_rejects_overlap_against_selected_fix() {
        let source = "abcdefghij";
        let fix_a = safe_fix("LINT_A", 0, None, 2, 6, "WXYZ");
        let fix_b = safe_fix("LINT_B", 0, None, 4, 8, "QRST");

        let plan = plan_fixes(
            source,
            vec![fix_b.clone(), fix_a.clone()],
            &[FixApplicability::Safe],
            &[],
        );

        assert_eq!(plan.accepted.len(), 1);
        assert_eq!(plan.accepted[0].rule_code, "LINT_A");
        assert_eq!(plan.blocked.len(), 1);
        assert!(plan.blocked[0].reasons.iter().any(|reason| matches!(
            reason,
            BlockedReason::OverlapWithSelectedFix { selected_rule_code }
                if selected_rule_code == "LINT_A"
        )));
    }

    #[test]
    fn planner_enforces_isolation_groups() {
        let source = "abcdefghij";
        let fix_a = safe_fix("LINT_A", 0, Some("group-1"), 0, 1, "A");
        let fix_b = safe_fix("LINT_B", 1, Some("group-1"), 8, 9, "Z");

        let plan = plan_fixes(
            source,
            vec![fix_b.clone(), fix_a.clone()],
            &[FixApplicability::Safe],
            &[],
        );

        assert_eq!(plan.accepted.len(), 1);
        assert_eq!(plan.accepted[0].rule_code, "LINT_A");
        assert_eq!(plan.blocked.len(), 1);
        assert!(plan.blocked[0].reasons.iter().any(|reason| matches!(
            reason,
            BlockedReason::IsolationGroupConflict {
                isolation_group,
                selected_rule_code
            } if isolation_group == "group-1" && selected_rule_code == "LINT_A"
        )));
    }

    #[test]
    fn apply_edits_is_deterministic() {
        let source = "0123456789";
        let edits = vec![Edit::replace(6, 8, "B"), Edit::replace(2, 4, "AA")];

        let forward = apply_edits(source, &edits);
        let reverse = apply_edits(source, &[edits[1].clone(), edits[0].clone()]);

        assert_eq!(forward, "01AA45B89");
        assert_eq!(reverse, "01AA45B89");
    }

    #[test]
    fn planner_blocks_edits_touching_protected_ranges() {
        let source = "SELECT 'literal' AS s -- note\nFROM {{ ref('users') }}";
        let protected = derive_protected_ranges(source, Dialect::Generic);

        assert!(protected
            .iter()
            .any(|range| range.kind == ProtectedRangeKind::SqlStringLiteral));
        assert!(protected
            .iter()
            .any(|range| range.kind == ProtectedRangeKind::SqlComment));
        assert!(protected
            .iter()
            .any(|range| range.kind == ProtectedRangeKind::TemplateTag));

        let users_start = source.find("users").expect("template target");
        let fix = safe_fix(
            "LINT_TP_001",
            0,
            None,
            users_start,
            users_start + 5,
            "orders",
        );

        let plan = plan_fixes(source, vec![fix], &[FixApplicability::Safe], &protected);
        assert!(plan.accepted.is_empty());
        assert_eq!(plan.blocked.len(), 1);
        assert!(plan.blocked[0].reasons.iter().any(|reason| matches!(
            reason,
            BlockedReason::TouchesProtectedRange {
                kind: ProtectedRangeKind::TemplateTag,
                ..
            }
        )));
    }

    #[test]
    fn planner_allows_lt05_edits_that_move_template_tags() {
        let source = "SELECT {{ foo }} FROM tbl";
        let protected = derive_protected_ranges(source, Dialect::Generic);
        let fix = safe_fix(
            "LINT_LT_005",
            0,
            None,
            0,
            source.len(),
            "SELECT {{ foo }}\nFROM tbl",
        );

        let plan = plan_fixes(source, vec![fix], &[FixApplicability::Safe], &protected);
        assert_eq!(plan.accepted.len(), 1);
        assert!(plan.blocked.is_empty());
    }
}
