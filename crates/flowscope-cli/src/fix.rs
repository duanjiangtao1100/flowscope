//! SQL lint auto-fix helpers.
//!
//! Fixing is best-effort and deterministic. We combine:
//! - AST rewrites for structurally safe transforms.
//! - Text rewrites for parity-style formatting/convention rules.
//! - Lint before/after comparison to report per-rule removed violations.

use flowscope_core::linter::config::canonicalize_rule_code;
use flowscope_core::{
    analyze, issue_codes, linter::helpers as lint_helpers, parse_sql_with_dialect, AnalysisOptions,
    AnalyzeRequest, Dialect, LintConfig, ParseError,
};
use sqlparser::ast::helpers::attached_token::AttachedToken;
use sqlparser::ast::*;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[must_use]
pub struct FixCounts {
    /// Per-rule fix counts, ordered by rule code for deterministic output.
    by_rule: BTreeMap<String, usize>,
}

impl FixCounts {
    pub fn total(&self) -> usize {
        self.by_rule.values().sum()
    }

    pub fn add(&mut self, code: &str, count: usize) {
        if count == 0 {
            return;
        }
        *self.by_rule.entry(code.to_string()).or_insert(0) += count;
    }

    pub fn get(&self, code: &str) -> usize {
        self.by_rule.get(code).copied().unwrap_or(0)
    }

    fn from_removed(before: &BTreeMap<String, usize>, after: &BTreeMap<String, usize>) -> Self {
        let mut out = Self::default();
        for (code, before_count) in before {
            let after_count = after.get(code).copied().unwrap_or(0);
            if *before_count > after_count {
                out.add(code, before_count - after_count);
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
#[must_use]
pub struct FixOutcome {
    pub sql: String,
    pub counts: FixCounts,
    pub changed: bool,
    pub skipped_due_to_comments: bool,
    pub skipped_due_to_regression: bool,
}

#[derive(Debug, Clone, Default)]
struct RuleFilter {
    disabled: HashSet<String>,
    am005_mode: Am005QualifyMode,
    cv06_require_final_semicolon: bool,
    al007_force_enable: bool,
    al009_case_check: Al009AliasCaseCheck,
    al001_mode: Al001FixMode,
    cv010_style: Cv010QuotedLiteralStyle,
    cv011_style: Cv011CastingStyle,
    st005_forbid_subquery_in: St005ForbidSubqueryIn,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
enum Am005QualifyMode {
    #[default]
    Inner,
    Outer,
    Both,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
enum Al001FixMode {
    #[default]
    Explicit,
    Implicit,
    PreserveOriginal,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
enum Al009AliasCaseCheck {
    #[default]
    Dialect,
    CaseInsensitive,
    QuotedCsNakedUpper,
    QuotedCsNakedLower,
    CaseSensitive,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
enum Cv010QuotedLiteralStyle {
    #[default]
    Consistent,
    SingleQuotes,
    DoubleQuotes,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
enum Cv011CastingStyle {
    #[default]
    Consistent,
    Shorthand,
    Cast,
    Convert,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
enum St005ForbidSubqueryIn {
    Both,
    #[default]
    Join,
    From,
}

impl St005ForbidSubqueryIn {
    fn forbid_from(self) -> bool {
        matches!(self, Self::Both | Self::From)
    }

    fn forbid_join(self) -> bool {
        matches!(self, Self::Both | Self::Join)
    }
}

impl RuleFilter {
    fn from_lint_config(lint_config: &LintConfig) -> Self {
        let disabled: HashSet<String> = lint_config
            .disabled_rules
            .iter()
            .filter_map(|rule| {
                let trimmed = rule.trim();
                if trimmed.is_empty() {
                    return None;
                }
                Some(
                    canonicalize_rule_code(trimmed).unwrap_or_else(|| trimmed.to_ascii_uppercase()),
                )
            })
            .collect();
        let am005_mode = match lint_config
            .rule_option_str(issue_codes::LINT_AM_005, "fully_qualify_join_types")
            .unwrap_or("inner")
            .to_ascii_lowercase()
            .as_str()
        {
            "outer" => Am005QualifyMode::Outer,
            "both" => Am005QualifyMode::Both,
            _ => Am005QualifyMode::Inner,
        };
        let cv06_require_final_semicolon = lint_config
            .rule_option_bool(issue_codes::LINT_CV_006, "require_final_semicolon")
            .unwrap_or(false);
        let al007_force_enable = lint_config
            .rule_option_bool(issue_codes::LINT_AL_007, "force_enable")
            .unwrap_or(false);
        let al009_case_check = match lint_config
            .rule_option_str(issue_codes::LINT_AL_009, "alias_case_check")
            .unwrap_or("dialect")
            .to_ascii_lowercase()
            .as_str()
        {
            "case_insensitive" => Al009AliasCaseCheck::CaseInsensitive,
            "quoted_cs_naked_upper" => Al009AliasCaseCheck::QuotedCsNakedUpper,
            "quoted_cs_naked_lower" => Al009AliasCaseCheck::QuotedCsNakedLower,
            "case_sensitive" => Al009AliasCaseCheck::CaseSensitive,
            _ => Al009AliasCaseCheck::Dialect,
        };
        let al001_mode = if disabled.contains(issue_codes::LINT_AL_001) {
            Al001FixMode::PreserveOriginal
        } else {
            match lint_config
                .rule_option_str(issue_codes::LINT_AL_001, "aliasing")
                .unwrap_or("explicit")
                .to_ascii_lowercase()
                .as_str()
            {
                "implicit" => Al001FixMode::Implicit,
                _ => Al001FixMode::Explicit,
            }
        };
        let cv010_style = match lint_config
            .rule_option_str(issue_codes::LINT_CV_010, "preferred_quoted_literal_style")
            .unwrap_or("consistent")
            .to_ascii_lowercase()
            .as_str()
        {
            "single_quotes" | "single" => Cv010QuotedLiteralStyle::SingleQuotes,
            "double_quotes" | "double" => Cv010QuotedLiteralStyle::DoubleQuotes,
            _ => Cv010QuotedLiteralStyle::Consistent,
        };
        let cv011_style = match lint_config
            .rule_option_str(issue_codes::LINT_CV_011, "preferred_type_casting_style")
            .unwrap_or("consistent")
            .to_ascii_lowercase()
            .as_str()
        {
            "shorthand" => Cv011CastingStyle::Shorthand,
            "cast" => Cv011CastingStyle::Cast,
            "convert" => Cv011CastingStyle::Convert,
            _ => Cv011CastingStyle::Consistent,
        };
        let st005_forbid_subquery_in = match lint_config
            .rule_option_str(issue_codes::LINT_ST_005, "forbid_subquery_in")
            .unwrap_or("join")
            .to_ascii_lowercase()
            .as_str()
        {
            "from" => St005ForbidSubqueryIn::From,
            "both" => St005ForbidSubqueryIn::Both,
            _ => St005ForbidSubqueryIn::Join,
        };
        Self {
            disabled,
            am005_mode,
            cv06_require_final_semicolon,
            al007_force_enable,
            al009_case_check,
            al001_mode,
            cv010_style,
            cv011_style,
            st005_forbid_subquery_in,
        }
    }

    #[cfg(test)]
    fn new(disabled_rules: &[String]) -> Self {
        Self::from_lint_config(&LintConfig {
            enabled: true,
            disabled_rules: disabled_rules.to_vec(),
            rule_configs: BTreeMap::new(),
        })
    }

    fn allows(&self, code: &str) -> bool {
        let canonical =
            canonicalize_rule_code(code).unwrap_or_else(|| code.trim().to_ascii_uppercase());
        !self.disabled.contains(&canonical)
    }
}

/// Apply deterministic lint fixes to a SQL document.
///
/// Notes:
/// - If comment markers are detected, auto-fix is skipped to avoid losing
///   comments when rendering SQL from AST.
/// - Parse errors are returned so callers can decide whether to continue linting.
pub fn apply_lint_fixes(
    sql: &str,
    dialect: Dialect,
    disabled_rules: &[String],
) -> Result<FixOutcome, ParseError> {
    apply_lint_fixes_with_lint_config(
        sql,
        dialect,
        &LintConfig {
            enabled: true,
            disabled_rules: disabled_rules.to_vec(),
            rule_configs: BTreeMap::new(),
        },
    )
}

pub fn apply_lint_fixes_with_lint_config(
    sql: &str,
    dialect: Dialect,
    lint_config: &LintConfig,
) -> Result<FixOutcome, ParseError> {
    let rule_filter = RuleFilter::from_lint_config(lint_config);

    if contains_comment_markers(sql, dialect) {
        return Ok(FixOutcome {
            sql: sql.to_string(),
            counts: FixCounts::default(),
            changed: false,
            skipped_due_to_comments: true,
            skipped_due_to_regression: false,
        });
    }

    let before_counts = lint_rule_counts(sql, dialect, lint_config);
    let mut statements = parse_sql_with_dialect(sql, dialect)?;
    for stmt in &mut statements {
        fix_statement(stmt, &rule_filter);
    }

    let mut fixed_sql = render_statements(&statements, sql);
    fixed_sql = apply_text_fixes(&fixed_sql, &rule_filter, dialect);
    fixed_sql = apply_am005_full_outer_keyword_fix(&fixed_sql, &rule_filter);
    fixed_sql = apply_al001_alias_style_fix(sql, &fixed_sql, dialect, &rule_filter);

    let after_counts = lint_rule_counts(&fixed_sql, dialect, lint_config);
    let counts = FixCounts::from_removed(&before_counts, &after_counts);

    if parse_errors_increased(&before_counts, &after_counts) {
        return Ok(FixOutcome {
            sql: sql.to_string(),
            counts: FixCounts::default(),
            changed: false,
            skipped_due_to_comments: false,
            skipped_due_to_regression: true,
        });
    }

    if counts.total() == 0 {
        // Regression guard: no rules improved. Flag as regression if total violations
        // actually increased (text-fix side effects introduced new violations).
        let before_total: usize = before_counts.values().sum();
        let after_total: usize = after_counts.values().sum();
        return Ok(FixOutcome {
            sql: sql.to_string(),
            counts,
            changed: false,
            skipped_due_to_comments: false,
            skipped_due_to_regression: after_total > before_total,
        });
    }
    let changed = fixed_sql != sql;

    Ok(FixOutcome {
        sql: fixed_sql,
        counts,
        changed,
        skipped_due_to_comments: false,
        skipped_due_to_regression: false,
    })
}

/// Check whether SQL contains comment markers outside of quoted regions.
fn contains_comment_markers(sql: &str, dialect: Dialect) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ScanMode {
        Outside,
        SingleQuote,
        DoubleQuote,
        BacktickQuote,
        BracketQuote,
    }

    let bytes = sql.as_bytes();
    let mut mode = ScanMode::Outside;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();

        match mode {
            ScanMode::Outside => {
                if b == b'\'' {
                    mode = ScanMode::SingleQuote;
                    i += 1;
                    continue;
                }
                if b == b'"' {
                    mode = ScanMode::DoubleQuote;
                    i += 1;
                    continue;
                }
                if b == b'`' {
                    mode = ScanMode::BacktickQuote;
                    i += 1;
                    continue;
                }
                if b == b'[' {
                    mode = ScanMode::BracketQuote;
                    i += 1;
                    continue;
                }

                if b == b'-' && next == Some(b'-') {
                    return true;
                }
                if b == b'/' && next == Some(b'*') {
                    return true;
                }
                if matches!(dialect, Dialect::Mysql) && b == b'#' {
                    return true;
                }

                i += 1;
            }
            ScanMode::SingleQuote => {
                if b == b'\'' && next == Some(b'\'') {
                    i += 2;
                } else if b == b'\'' {
                    mode = ScanMode::Outside;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            ScanMode::DoubleQuote => {
                if b == b'"' && next == Some(b'"') {
                    i += 2;
                } else if b == b'"' {
                    mode = ScanMode::Outside;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            ScanMode::BacktickQuote => {
                if b == b'`' && next == Some(b'`') {
                    i += 2;
                } else if b == b'`' {
                    mode = ScanMode::Outside;
                    i += 1;
                } else {
                    i += 1;
                }
            }
            ScanMode::BracketQuote => {
                if b == b']' && next == Some(b']') {
                    i += 2;
                } else if b == b']' {
                    mode = ScanMode::Outside;
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
    }

    false
}

fn render_statements(statements: &[Statement], original: &str) -> String {
    let mut rendered = statements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(";\n");

    if statements.len() > 1 || original.trim_end().ends_with(';') {
        rendered.push(';');
    }

    rendered
}

fn lint_rule_counts(
    sql: &str,
    dialect: Dialect,
    lint_config: &LintConfig,
) -> BTreeMap<String, usize> {
    let request = AnalyzeRequest {
        sql: sql.to_string(),
        files: None,
        dialect,
        source_name: None,
        options: Some(AnalysisOptions {
            lint: Some(lint_config.clone()),
            ..Default::default()
        }),
        schema: None,
        #[cfg(feature = "templating")]
        template_config: None,
    };

    let mut counts = BTreeMap::new();
    for issue in analyze(&request)
        .issues
        .into_iter()
        .filter(|issue| issue.code.starts_with("LINT_") || issue.code == issue_codes::PARSE_ERROR)
    {
        *counts.entry(issue.code).or_insert(0usize) += 1;
    }
    counts
}

fn parse_errors_increased(
    before_counts: &BTreeMap<String, usize>,
    after_counts: &BTreeMap<String, usize>,
) -> bool {
    after_counts
        .get(issue_codes::PARSE_ERROR)
        .copied()
        .unwrap_or(0)
        > before_counts
            .get(issue_codes::PARSE_ERROR)
            .copied()
            .unwrap_or(0)
}

fn apply_text_fixes(sql: &str, rule_filter: &RuleFilter, dialect: Dialect) -> String {
    let mut out = sql.to_string();

    if rule_filter.allows(issue_codes::LINT_JJ_001) {
        out = fix_jinja_padding(&out);
    }
    if rule_filter.allows(issue_codes::LINT_ST_012) {
        out = fix_consecutive_semicolons(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_CV_006) {
        out = fix_statement_terminators(&out, dialect, rule_filter.cv06_require_final_semicolon);
    }
    if rule_filter.allows(issue_codes::LINT_CV_001) {
        out = fix_not_equal_operator(&out);
    }
    if rule_filter.allows(issue_codes::LINT_CV_003) {
        out = fix_trailing_select_comma(&out);
    }
    if rule_filter.allows(issue_codes::LINT_LT_013) {
        out = fix_leading_blank_lines(&out);
    }
    if rule_filter.allows(issue_codes::LINT_LT_015) {
        out = fix_excessive_blank_lines(&out);
    }
    if rule_filter.allows(issue_codes::LINT_LT_001) {
        out = fix_operator_spacing(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_003) {
        out = fix_operator_line_position(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_004) {
        out = fix_comma_spacing(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_006) {
        out = fix_function_spacing(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_005) {
        out = fix_long_lines(&out);
    }
    if rule_filter.allows(issue_codes::LINT_LT_011) {
        out = fix_set_operator_layout(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_007) {
        out = fix_cte_bracket(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_008) {
        out = fix_cte_newline(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_009) {
        out = fix_select_target_newline(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_LT_010) {
        out = fix_select_modifier_position(&out);
    }
    if rule_filter.allows(issue_codes::LINT_LT_014) {
        out = fix_keyword_newlines(&out, dialect);
    }
    if rule_filter.allows(issue_codes::LINT_AL_005) {
        out = fix_unused_table_aliases(&out);
    }
    if rule_filter.allows(issue_codes::LINT_RF_004) {
        out = fix_table_alias_keywords(&out);
    }
    if rule_filter.allows(issue_codes::LINT_ST_005) {
        out = fix_subquery_to_cte(&out);
    }
    if rule_filter.allows(issue_codes::LINT_CV_010) {
        out = fix_quoted_literal_style(&out, rule_filter.cv010_style);
    }
    if rule_filter.allows(issue_codes::LINT_RF_003) {
        out = fix_mixed_reference_qualification(&out);
    }
    if rule_filter.allows(issue_codes::LINT_RF_006) {
        out = fix_references_quoting(&out);
    }
    if rule_filter.allows(issue_codes::LINT_CP_001)
        || rule_filter.allows(issue_codes::LINT_CP_004)
        || rule_filter.allows(issue_codes::LINT_CP_005)
    {
        out = fix_case_style_consistency(&out);
    }
    if rule_filter.allows(issue_codes::LINT_TQ_002) {
        out = fix_tsql_procedure_begin_end(&out);
    }
    if rule_filter.allows(issue_codes::LINT_TQ_003) {
        out = fix_tsql_empty_batches(&out);
    }
    if rule_filter.allows(issue_codes::LINT_LT_012) {
        out = fix_trailing_newline(&out);
    }

    out
}

fn apply_am005_full_outer_keyword_fix(sql: &str, rule_filter: &RuleFilter) -> String {
    if !rule_filter.allows(issue_codes::LINT_AM_005) {
        return sql.to_string();
    }

    if !matches!(
        rule_filter.am005_mode,
        Am005QualifyMode::Outer | Am005QualifyMode::Both
    ) {
        return sql.to_string();
    }

    replace_full_join_outside_single_quotes(sql)
}

fn apply_al001_alias_style_fix(
    original_sql: &str,
    fixed_sql: &str,
    dialect: Dialect,
    rule_filter: &RuleFilter,
) -> String {
    match rule_filter.al001_mode {
        Al001FixMode::Explicit => fixed_sql.to_string(),
        Al001FixMode::Implicit => rewrite_table_aliases_to_implicit(fixed_sql, dialect),
        Al001FixMode::PreserveOriginal => {
            preserve_original_table_alias_style(original_sql, fixed_sql, dialect)
        }
    }
}

#[derive(Debug, Clone)]
struct TableAliasOccurrence {
    alias_key: String,
    alias_start: usize,
    explicit_as: bool,
    as_start: Option<usize>,
}

fn preserve_original_table_alias_style(
    original_sql: &str,
    fixed_sql: &str,
    dialect: Dialect,
) -> String {
    let Some(original_aliases) = table_alias_occurrences(original_sql, dialect) else {
        return fixed_sql.to_string();
    };
    let Some(fixed_aliases) = table_alias_occurrences(fixed_sql, dialect) else {
        return fixed_sql.to_string();
    };

    let mut desired_by_alias: HashMap<String, VecDeque<bool>> = HashMap::new();
    for alias in original_aliases {
        desired_by_alias
            .entry(alias.alias_key)
            .or_default()
            .push_back(alias.explicit_as);
    }

    let mut removals = Vec::new();
    for alias in fixed_aliases {
        let desired_explicit = desired_by_alias
            .get_mut(&alias.alias_key)
            .and_then(VecDeque::pop_front)
            .unwrap_or(alias.explicit_as);

        if alias.explicit_as && !desired_explicit {
            if let Some(as_start) = alias.as_start {
                removals.push((as_start, alias.alias_start));
            }
        }
    }

    apply_byte_removals(fixed_sql, removals)
}

fn rewrite_table_aliases_to_implicit(sql: &str, dialect: Dialect) -> String {
    let Some(aliases) = table_alias_occurrences(sql, dialect) else {
        return sql.to_string();
    };

    let removals = aliases
        .into_iter()
        .filter_map(|alias| {
            if alias.explicit_as {
                alias.as_start.map(|as_start| (as_start, alias.alias_start))
            } else {
                None
            }
        })
        .collect();

    apply_byte_removals(sql, removals)
}

fn apply_byte_removals(sql: &str, mut removals: Vec<(usize, usize)>) -> String {
    if removals.is_empty() {
        return sql.to_string();
    }

    removals.sort_unstable();
    removals.dedup();

    let mut out = sql.to_string();
    for (start, end) in removals.into_iter().rev() {
        if start < end && end <= out.len() {
            out.replace_range(start..end, "");
        }
    }
    out
}

#[derive(Debug, Clone)]
struct SpanEdit {
    start: usize,
    end: usize,
    replacement: String,
}

impl SpanEdit {
    fn replace(start: usize, end: usize, replacement: impl Into<String>) -> Self {
        Self {
            start,
            end,
            replacement: replacement.into(),
        }
    }
}

fn apply_span_edits(sql: &str, mut edits: Vec<SpanEdit>) -> String {
    if edits.is_empty() {
        return sql.to_string();
    }

    edits.sort_by_key(|edit| (edit.start, edit.end));
    edits.dedup_by(|a, b| a.start == b.start && a.end == b.end && a.replacement == b.replacement);

    let mut out = sql.to_string();
    let mut last_start = usize::MAX;
    for edit in edits.into_iter().rev() {
        if edit.start > edit.end || edit.end > out.len() {
            continue;
        }
        if edit.start >= last_start {
            continue;
        }
        out.replace_range(edit.start..edit.end, &edit.replacement);
        last_start = edit.start;
    }

    out
}

fn table_alias_occurrences(sql: &str, dialect: Dialect) -> Option<Vec<TableAliasOccurrence>> {
    let statements = parse_sql_with_dialect(sql, dialect).ok()?;
    let tokens = tokenize_with_offsets(sql, dialect)?;

    let mut aliases = Vec::new();
    for statement in &statements {
        collect_table_alias_idents_in_statement(statement, &mut |ident| {
            aliases.push(ident.clone())
        });
    }

    let mut occurrences = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let (alias_start, _alias_end) = ident_span_offsets(sql, &alias)?;
        let previous_token = tokens
            .iter()
            .rev()
            .find(|token| token.end <= alias_start && !is_trivia_token(&token.token));

        let (explicit_as, as_start) = match previous_token {
            Some(token) if is_as_token(&token.token) => (true, Some(token.start)),
            _ => (false, None),
        };

        occurrences.push(TableAliasOccurrence {
            alias_key: alias.value.to_ascii_lowercase(),
            alias_start,
            explicit_as,
            as_start,
        });
    }

    Some(occurrences)
}

fn ident_span_offsets(sql: &str, ident: &Ident) -> Option<(usize, usize)> {
    let start = line_col_to_offset(
        sql,
        ident.span.start.line as usize,
        ident.span.start.column as usize,
    )?;
    let end = line_col_to_offset(
        sql,
        ident.span.end.line as usize,
        ident.span.end.column as usize,
    )?;
    Some((start, end))
}

fn is_as_token(token: &Token) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case("AS"))
}

fn replace_full_join_outside_single_quotes(sql: &str) -> String {
    const NEEDLE: &[u8] = b"FULL JOIN";
    const REPLACEMENT: &str = "full outer join";

    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len() + 16);
    let mut idx = 0usize;
    let mut in_single = false;

    while idx < bytes.len() {
        if bytes[idx] == b'\'' {
            if in_single && idx + 1 < bytes.len() && bytes[idx + 1] == b'\'' {
                out.push_str("''");
                idx += 2;
                continue;
            }
            in_single = !in_single;
            out.push('\'');
            idx += 1;
            continue;
        }

        if !in_single
            && idx + NEEDLE.len() <= bytes.len()
            && equals_ignore_ascii_case(&bytes[idx..idx + NEEDLE.len()], NEEDLE)
            && keyword_boundary(bytes, idx.saturating_sub(1), idx)
            && keyword_boundary(bytes, idx + NEEDLE.len(), idx + NEEDLE.len())
        {
            out.push_str(REPLACEMENT);
            idx += NEEDLE.len();
            continue;
        }

        out.push(bytes[idx] as char);
        idx += 1;
    }

    out
}

fn equals_ignore_ascii_case(left: &[u8], right_upper_ascii: &[u8]) -> bool {
    left.len() == right_upper_ascii.len()
        && left
            .iter()
            .zip(right_upper_ascii)
            .all(|(l, r)| l.to_ascii_uppercase() == *r)
}

fn keyword_boundary(bytes: &[u8], check_idx: usize, idx: usize) -> bool {
    if idx == 0 || idx >= bytes.len() {
        return true;
    }
    let ch = bytes[check_idx] as char;
    !(ch.is_ascii_alphanumeric() || ch == '_')
}

fn fix_jinja_padding(sql: &str) -> String {
    let out = normalize_template_tag_padding(sql, b"{{", b"}}", |b| b != b'{' && b != b'}');
    normalize_template_tag_padding(&out, b"{%", b"%}", |b| b != b'%')
}

fn normalize_template_tag_padding<F>(sql: &str, open: &[u8], close: &[u8], inner_ok: F) -> String
where
    F: Fn(u8) -> bool,
{
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let mut replaced = false;
        if i + open.len() <= bytes.len() && &bytes[i..i + open.len()] == open {
            let mut j = i + open.len();
            while j + close.len() <= bytes.len() {
                if &bytes[j..j + close.len()] == close {
                    let inner = &sql[i + open.len()..j];
                    if !inner.is_empty() && inner.as_bytes().iter().copied().all(&inner_ok) {
                        out.push_str(std::str::from_utf8(open).expect("template delimiter ascii"));
                        out.push(' ');
                        out.push_str(inner.trim());
                        out.push(' ');
                        out.push_str(std::str::from_utf8(close).expect("template delimiter ascii"));
                        i = j + close.len();
                        replaced = true;
                    }
                    break;
                }
                j += 1;
            }
            if replaced {
                continue;
            }
        }

        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

fn fix_consecutive_semicolons(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return collapse_semicolon_runs_without_tokenizer(sql);
    };

    let mut out = String::with_capacity(sql.len());
    let mut cursor = 0usize;
    let mut idx = 0usize;

    while idx < tokens.len() {
        if !matches!(tokens[idx].token, Token::SemiColon) {
            idx += 1;
            continue;
        }

        let mut j = idx + 1;
        let mut semicolon_count = 1usize;
        let mut last_semicolon_end = tokens[idx].end;

        while j < tokens.len() {
            match &tokens[j].token {
                Token::SemiColon => {
                    semicolon_count += 1;
                    last_semicolon_end = tokens[j].end;
                    j += 1;
                }
                token if is_trivia_token(token) => {
                    j += 1;
                }
                _ => break,
            }
        }

        if semicolon_count < 2 {
            idx += 1;
            continue;
        }

        let run_start = tokens[idx].start;
        if run_start > cursor {
            out.push_str(&sql[cursor..run_start]);
        }
        out.push(';');
        cursor = last_semicolon_end;
        idx = j;
    }

    if cursor == 0 {
        return sql.to_string();
    }

    out.push_str(&sql[cursor..]);
    out
}

fn fix_statement_terminators(sql: &str, dialect: Dialect, require_final_semicolon: bool) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    if tokens.is_empty() {
        return sql.to_string();
    }

    let mut edits = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        if !matches!(token.token, Token::SemiColon) {
            continue;
        }
        if let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) {
            let gap_start = tokens[prev_idx].end;
            let gap_end = token.start;
            if gap_start < gap_end {
                let gap = &sql[gap_start..gap_end];
                if !gap.contains('\n') && gap.chars().all(char::is_whitespace) {
                    edits.push(SpanEdit::replace(gap_start, gap_end, ""));
                }
            }
        }
    }

    if require_final_semicolon {
        if let Some(last_idx) = last_non_trivia_token(&tokens) {
            if !matches!(tokens[last_idx].token, Token::SemiColon) {
                let insert_at = tokens[last_idx].end;
                edits.push(SpanEdit::replace(insert_at, insert_at, ";"));
            }
        }
    }

    apply_span_edits(sql, edits)
}

fn collapse_semicolon_runs_without_tokenizer(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b';' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let mut j = i + 1;
        let mut semicolon_count = 1usize;
        let mut scan = j;
        while scan < bytes.len() {
            while scan < bytes.len() && is_ascii_whitespace_byte(bytes[scan]) {
                scan += 1;
            }
            if scan < bytes.len() && bytes[scan] == b';' {
                semicolon_count += 1;
                scan += 1;
                j = scan;
            } else {
                break;
            }
        }

        if semicolon_count >= 2 {
            out.push(';');
            i = j;
        } else {
            out.push(';');
            i += 1;
        }
    }

    out
}

fn fix_not_equal_operator(sql: &str) -> String {
    replace_outside_single_quotes(sql, |segment| segment.replace("<>", "!="))
}

fn fix_trailing_select_comma(sql: &str) -> String {
    replace_comma_before_from_keyword(sql)
}

fn replace_comma_before_from_keyword(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b',' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let mut j = i + 1;
        while j < bytes.len() && is_ascii_whitespace_byte(bytes[j]) {
            j += 1;
        }

        if let Some(from_end) = match_ascii_keyword_at(bytes, j, b"FROM") {
            out.push(' ');
            out.push_str(&sql[j..from_end]);
            i = from_end;
        } else {
            out.push(',');
            i += 1;
        }
    }

    out
}

fn replace_outside_single_quotes<F>(sql: &str, mut transform: F) -> String
where
    F: FnMut(&str) -> String,
{
    let mut out = String::with_capacity(sql.len());
    let mut outside = String::new();
    let mut chars = sql.chars().peekable();
    let mut in_single = false;

    while let Some(ch) = chars.next() {
        if in_single {
            out.push(ch);
            if ch == '\'' {
                if matches!(chars.peek(), Some('\'')) {
                    out.push(chars.next().expect("peek confirmed quote"));
                } else {
                    in_single = false;
                }
            }
            continue;
        }

        if ch == '\'' {
            if !outside.is_empty() {
                out.push_str(&transform(&outside));
                outside.clear();
            }
            out.push(ch);
            in_single = true;
            continue;
        }

        outside.push(ch);
    }

    if !outside.is_empty() {
        out.push_str(&transform(&outside));
    }

    out
}

fn fix_leading_blank_lines(sql: &str) -> String {
    let first_non_ws = sql
        .char_indices()
        .find(|(_, ch)| !ch.is_whitespace())
        .map(|(idx, _)| idx)
        .unwrap_or(sql.len());
    let leading = &sql[..first_non_ws];
    let Some(last_newline) = leading.rfind('\n') else {
        return sql.to_string();
    };
    sql[last_newline + 1..].to_string()
}

fn fix_excessive_blank_lines(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'\n' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let mut j = i + 1;
        let mut newline_count = 1usize;
        while j < bytes.len() {
            let mut k = j;
            while k < bytes.len() && is_ascii_whitespace_byte(bytes[k]) && bytes[k] != b'\n' {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'\n' {
                newline_count += 1;
                j = k + 1;
            } else {
                break;
            }
        }

        if newline_count >= 3 {
            out.push_str("\n\n");
            i = j;
        } else {
            out.push('\n');
            i += 1;
        }
    }

    out
}

fn fix_operator_spacing(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        if !is_spacing_operator_token(&token.token) {
            continue;
        }
        let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) else {
            continue;
        };
        let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) else {
            continue;
        };

        let before_start = tokens[prev_idx].end;
        let before_end = token.start;
        if before_start <= before_end {
            let gap = &sql[before_start..before_end];
            if !gap.contains('\n') && !gap.contains('\r') && gap != " " {
                edits.push(SpanEdit::replace(before_start, before_end, " "));
            }
        }

        let after_start = token.end;
        let after_end = tokens[next_idx].start;
        if after_start <= after_end {
            let gap = &sql[after_start..after_end];
            if !gap.contains('\n') && !gap.contains('\r') && gap != " " {
                edits.push(SpanEdit::replace(after_start, after_end, " "));
            }
        }
    }

    apply_span_edits(sql, edits)
}

fn fix_operator_line_position(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        if !is_spacing_operator_token(&token.token) {
            continue;
        }
        let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) else {
            continue;
        };
        let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) else {
            continue;
        };

        let before_start = tokens[prev_idx].end;
        let before_end = token.start;
        let after_start = token.end;
        let after_end = tokens[next_idx].start;
        if before_start >= before_end || after_start >= after_end {
            continue;
        }

        let before_gap = &sql[before_start..before_end];
        let after_gap = &sql[after_start..after_end];
        if !before_gap.contains('\n') && after_gap.contains('\n') {
            edits.push(SpanEdit::replace(before_start, before_end, "\n"));
            edits.push(SpanEdit::replace(after_start, after_end, " "));
        }
    }

    apply_span_edits(sql, edits)
}

fn fix_comma_spacing(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        if !matches!(token.token, Token::Comma) {
            continue;
        }

        if let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) {
            let gap_start = tokens[prev_idx].end;
            let gap_end = token.start;
            if gap_start < gap_end {
                let gap = &sql[gap_start..gap_end];
                if !gap.contains('\n') && !gap.contains('\r') && !gap.is_empty() {
                    edits.push(SpanEdit::replace(gap_start, gap_end, ""));
                }
            }
        }

        if let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) {
            let gap_start = token.end;
            let gap_end = tokens[next_idx].start;
            if gap_start <= gap_end {
                let gap = &sql[gap_start..gap_end];
                if !gap.contains('\n') && !gap.contains('\r') && gap != " " {
                    edits.push(SpanEdit::replace(gap_start, gap_end, " "));
                }
            }
        }
    }

    apply_span_edits(sql, edits)
}

fn fix_function_spacing(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        let Token::Word(word) = &token.token else {
            continue;
        };
        let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) else {
            continue;
        };
        if !matches!(tokens[next_idx].token, Token::LParen) {
            continue;
        }
        if is_sql_keyword(&word.value) {
            continue;
        }

        let gap_start = token.end;
        let gap_end = tokens[next_idx].start;
        if gap_start < gap_end {
            edits.push(SpanEdit::replace(gap_start, gap_end, ""));
        }
    }

    apply_span_edits(sql, edits)
}

/// Maximum line length before `fix_long_lines` will attempt to split.
const MAX_LINE_LENGTH: usize = 300;
/// Target split position when breaking long lines.
const LINE_SPLIT_TARGET: usize = 280;

fn fix_long_lines(sql: &str) -> String {
    let mut out = String::new();
    for (idx, line) in sql.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        if line.len() <= MAX_LINE_LENGTH {
            out.push_str(line);
            continue;
        }

        let mut remaining = line.trim_start();
        let mut first_segment = true;
        while remaining.len() > MAX_LINE_LENGTH {
            let probe = remaining
                .char_indices()
                .take_while(|(i, _)| *i <= LINE_SPLIT_TARGET)
                .map(|(i, _)| i)
                .last()
                .unwrap_or(LINE_SPLIT_TARGET.min(remaining.len()));
            let split_at = remaining[..probe].rfind(' ').unwrap_or(probe);
            if !first_segment {
                out.push('\n');
            }
            out.push_str(remaining[..split_at].trim_end());
            out.push('\n');
            remaining = remaining[split_at..].trim_start();
            first_segment = false;
        }
        out.push_str(remaining);
    }
    out
}

fn fix_set_operator_layout(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();
    let mut idx = 0usize;

    while idx < tokens.len() {
        if !token_matches_keyword(&tokens[idx].token, "UNION")
            && !token_matches_keyword(&tokens[idx].token, "INTERSECT")
            && !token_matches_keyword(&tokens[idx].token, "EXCEPT")
        {
            idx += 1;
            continue;
        }

        let op_start = tokens[idx].start;
        let mut op_end = tokens[idx].end;
        if token_matches_keyword(&tokens[idx].token, "UNION") {
            if let Some(all_idx) = next_non_trivia_token(&tokens, idx + 1) {
                if token_matches_keyword(&tokens[all_idx].token, "ALL") {
                    op_end = tokens[all_idx].end;
                }
            }
        }

        if let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) {
            let gap_start = tokens[prev_idx].end;
            if gap_start < op_start {
                edits.push(SpanEdit::replace(gap_start, op_start, "\n"));
            }
        }
        if let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) {
            let gap_end = tokens[next_idx].start;
            if op_end < gap_end {
                edits.push(SpanEdit::replace(op_end, gap_end, "\n"));
            }
        }
        idx += 1;
    }

    apply_span_edits(sql, edits)
}

fn fix_cte_bracket(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for idx in 0..tokens.len() {
        if !token_matches_keyword(&tokens[idx].token, "AS") {
            continue;
        }
        let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) else {
            continue;
        };
        if token_simple_identifier(&tokens[prev_idx].token).is_none() {
            continue;
        }
        let Some(before_prev_idx) = prev_non_trivia_token(&tokens, prev_idx) else {
            continue;
        };
        if !token_matches_keyword(&tokens[before_prev_idx].token, "WITH")
            && !matches!(tokens[before_prev_idx].token, Token::Comma)
        {
            continue;
        }
        let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) else {
            continue;
        };
        if !token_matches_keyword(&tokens[next_idx].token, "SELECT") {
            continue;
        }
        edits.push(SpanEdit::replace(
            tokens[next_idx].start,
            tokens[next_idx].start,
            "(",
        ));
    }

    apply_span_edits(sql, edits)
}

fn fix_cte_newline(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for (idx, token) in tokens.iter().enumerate() {
        if !matches!(token.token, Token::RParen) {
            continue;
        }
        let Some(next_idx) = next_non_trivia_token(&tokens, idx + 1) else {
            continue;
        };
        if !token_matches_keyword(&tokens[next_idx].token, "SELECT") {
            continue;
        }
        let gap_start = token.end;
        let gap_end = tokens[next_idx].start;
        if gap_start < gap_end {
            let gap = &sql[gap_start..gap_end];
            if !gap.contains('\n') && !gap.contains('\r') {
                edits.push(SpanEdit::replace(gap_start, gap_end, "\n"));
            }
        }
    }

    apply_span_edits(sql, edits)
}

fn fix_select_target_newline(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();
    let mut i = 0usize;

    while i < tokens.len() {
        if !token_matches_keyword(&tokens[i].token, "SELECT") {
            i += 1;
            continue;
        }

        let mut depth = 0usize;
        let mut comma_count = 0usize;
        let mut from_idx = None;
        let mut j = i + 1;
        while j < tokens.len() {
            if is_trivia_token(&tokens[j].token) {
                j += 1;
                continue;
            }
            match tokens[j].token {
                Token::LParen => depth += 1,
                Token::RParen => depth = depth.saturating_sub(1),
                Token::Comma if depth == 0 => comma_count += 1,
                Token::SemiColon if depth == 0 => break,
                _ => {}
            }
            if depth == 0 && token_matches_keyword(&tokens[j].token, "FROM") {
                from_idx = Some(j);
                break;
            }
            j += 1;
        }

        if comma_count >= 4 {
            if let Some(from_idx) = from_idx {
                if let Some(prev_idx) = prev_non_trivia_token(&tokens, from_idx) {
                    let gap_start = tokens[prev_idx].end;
                    let gap_end = tokens[from_idx].start;
                    if gap_start < gap_end {
                        edits.push(SpanEdit::replace(gap_start, gap_end, "\n"));
                    }
                }
            }
        }

        i += 1;
    }

    apply_span_edits(sql, edits)
}

fn fix_keyword_newlines(sql: &str, dialect: Dialect) -> String {
    let Some(tokens) = tokenize_with_offsets(sql, dialect) else {
        return sql.to_string();
    };
    let mut edits = Vec::new();

    for idx in 0..tokens.len() {
        let is_major_keyword = token_matches_keyword(&tokens[idx].token, "FROM")
            || token_matches_keyword(&tokens[idx].token, "WHERE");
        let is_major_phrase = (token_matches_keyword(&tokens[idx].token, "GROUP")
            || token_matches_keyword(&tokens[idx].token, "ORDER"))
            && next_non_trivia_token(&tokens, idx + 1)
                .is_some_and(|next_idx| token_matches_keyword(&tokens[next_idx].token, "BY"));

        if !(is_major_keyword || is_major_phrase) {
            continue;
        }

        if let Some(prev_idx) = prev_non_trivia_token(&tokens, idx) {
            let gap_start = tokens[prev_idx].end;
            let gap_end = tokens[idx].start;
            if gap_start < gap_end {
                edits.push(SpanEdit::replace(gap_start, gap_end, "\n"));
            }
        }
    }

    apply_span_edits(sql, edits)
}

fn fix_select_modifier_position(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(select_end) = match_ascii_keyword_at(bytes, i, b"SELECT") else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };

        let mut j = select_end;
        let mut saw_newline = false;
        while j < bytes.len() && is_ascii_whitespace_byte(bytes[j]) {
            if bytes[j] == b'\n' {
                saw_newline = true;
            }
            j += 1;
        }

        if saw_newline {
            let modifier_end = match_ascii_keyword_at(bytes, j, b"DISTINCT")
                .or_else(|| match_ascii_keyword_at(bytes, j, b"ALL"));
            if let Some(modifier_end) = modifier_end {
                out.push_str(&sql[i..select_end]);
                out.push(' ');
                out.push_str(&sql[j..modifier_end]);
                i = modifier_end;
                continue;
            }
        }

        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

fn fix_unused_table_aliases(sql: &str) -> String {
    let Some(decls) = collect_simple_table_alias_declarations(sql, Dialect::Generic) else {
        return sql.to_string();
    };
    if decls.is_empty() {
        return sql.to_string();
    }

    let mut seen_aliases = HashSet::new();
    let mut removals = Vec::new();
    for decl in &decls {
        let alias_key = decl.alias.to_ascii_lowercase();
        if !seen_aliases.insert(alias_key.clone()) {
            continue;
        }
        if is_sql_keyword(&decl.alias) || is_generated_alias_identifier(&decl.alias) {
            continue;
        }
        if contains_alias_qualifier(sql, &decl.alias) {
            continue;
        }

        removals.extend(
            decls
                .iter()
                .filter(|candidate| candidate.alias.eq_ignore_ascii_case(&alias_key))
                .map(|candidate| (candidate.table_end, candidate.alias_end)),
        );
    }

    apply_byte_removals(sql, removals)
}

fn is_ascii_whitespace_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn is_ascii_whitespace_non_newline_byte(byte: u8) -> bool {
    is_ascii_whitespace_byte(byte) && byte != b'\n'
}

fn is_ascii_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ascii_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_simple_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !is_ascii_ident_start(bytes[0]) {
        return false;
    }
    bytes[1..].iter().copied().all(is_ascii_ident_continue)
}

fn is_simple_qualified_identifier(value: &str) -> bool {
    let mut parts = value.split('.');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(left), Some(right), None) => {
            is_simple_identifier(left) && is_simple_identifier(right)
        }
        _ => false,
    }
}

fn skip_ascii_whitespace(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && is_ascii_whitespace_byte(bytes[idx]) {
        idx += 1;
    }
    idx
}

fn consume_ascii_identifier(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() || !is_ascii_ident_start(bytes[start]) {
        return None;
    }
    let mut idx = start + 1;
    while idx < bytes.len() && is_ascii_ident_continue(bytes[idx]) {
        idx += 1;
    }
    Some(idx)
}

fn is_word_boundary_for_keyword(bytes: &[u8], idx: usize) -> bool {
    idx == 0 || idx >= bytes.len() || !is_ascii_ident_continue(bytes[idx])
}

fn match_ascii_keyword_at(bytes: &[u8], start: usize, keyword_upper: &[u8]) -> Option<usize> {
    let end = start.checked_add(keyword_upper.len())?;
    if end > bytes.len() {
        return None;
    }
    if !is_word_boundary_for_keyword(bytes, start.saturating_sub(1))
        || !is_word_boundary_for_keyword(bytes, end)
    {
        return None;
    }
    let matches = bytes[start..end]
        .iter()
        .zip(keyword_upper.iter())
        .all(|(actual, expected)| actual.to_ascii_uppercase() == *expected);
    if matches {
        Some(end)
    } else {
        None
    }
}

fn find_ascii_keyword(bytes: &[u8], keyword_upper: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + keyword_upper.len() <= bytes.len() {
        if match_ascii_keyword_at(bytes, i, keyword_upper).is_some() {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone)]
struct SimpleTableAliasDecl {
    keyword_start: usize,
    keyword_end: usize,
    table_start: usize,
    table_end: usize,
    alias_end: usize,
    alias: String,
    explicit_as: bool,
}

fn collect_simple_table_alias_declarations(
    sql: &str,
    dialect: Dialect,
) -> Option<Vec<SimpleTableAliasDecl>> {
    let tokens = tokenize_with_offsets(sql, dialect)?;
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < tokens.len() {
        if !token_matches_keyword(&tokens[i].token, "FROM")
            && !token_matches_keyword(&tokens[i].token, "JOIN")
        {
            i += 1;
            continue;
        }

        let keyword_start = tokens[i].start;
        let keyword_end = tokens[i].end;

        let Some(mut cursor) = next_non_trivia_token(&tokens, i + 1) else {
            i += 1;
            continue;
        };
        let Some(_) = token_simple_identifier(&tokens[cursor].token) else {
            i += 1;
            continue;
        };
        let table_start = tokens[cursor].start;
        let mut table_end = tokens[cursor].end;
        cursor += 1;

        loop {
            let Some(dot_idx) = next_non_trivia_token(&tokens, cursor) else {
                break;
            };
            if !matches!(tokens[dot_idx].token, Token::Period) {
                break;
            }
            let Some(next_idx) = next_non_trivia_token(&tokens, dot_idx + 1) else {
                break;
            };
            if token_simple_identifier(&tokens[next_idx].token).is_none() {
                break;
            }
            table_end = tokens[next_idx].end;
            cursor = next_idx + 1;
        }

        let Some(mut alias_idx) = next_non_trivia_token(&tokens, cursor) else {
            i += 1;
            continue;
        };
        let mut explicit_as = false;
        if token_matches_keyword(&tokens[alias_idx].token, "AS") {
            explicit_as = true;
            let Some(next_idx) = next_non_trivia_token(&tokens, alias_idx + 1) else {
                i += 1;
                continue;
            };
            alias_idx = next_idx;
        }

        let Some(alias_value) = token_simple_identifier(&tokens[alias_idx].token) else {
            i += 1;
            continue;
        };

        out.push(SimpleTableAliasDecl {
            keyword_start,
            keyword_end,
            table_start,
            table_end,
            alias_end: tokens[alias_idx].end,
            alias: alias_value.to_string(),
            explicit_as,
        });
        i = alias_idx + 1;
    }

    Some(out)
}

fn next_non_trivia_token(tokens: &[LocatedToken], mut start: usize) -> Option<usize> {
    while start < tokens.len() {
        if !is_trivia_token(&tokens[start].token) {
            return Some(start);
        }
        start += 1;
    }
    None
}

fn prev_non_trivia_token(tokens: &[LocatedToken], start: usize) -> Option<usize> {
    if start == 0 {
        return None;
    }
    let mut idx = start - 1;
    loop {
        if !is_trivia_token(&tokens[idx].token) {
            return Some(idx);
        }
        if idx == 0 {
            return None;
        }
        idx -= 1;
    }
}

fn last_non_trivia_token(tokens: &[LocatedToken]) -> Option<usize> {
    (0..tokens.len())
        .rev()
        .find(|idx| !is_trivia_token(&tokens[*idx].token))
}

fn token_matches_keyword(token: &Token, keyword: &str) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case(keyword))
}

fn token_simple_identifier(token: &Token) -> Option<&str> {
    match token {
        Token::Word(word) if is_simple_identifier(&word.value) => Some(&word.value),
        _ => None,
    }
}

fn contains_alias_qualifier(sql: &str, alias: &str) -> bool {
    let alias_bytes = alias.as_bytes();
    if alias_bytes.is_empty() {
        return false;
    }
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    while i + alias_bytes.len() < bytes.len() {
        if !is_word_boundary_for_keyword(bytes, i.saturating_sub(1)) {
            i += 1;
            continue;
        }

        let end = i + alias_bytes.len();
        if end < bytes.len()
            && bytes[end] == b'.'
            && bytes[i..end]
                .iter()
                .zip(alias_bytes.iter())
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        {
            return true;
        }
        i += 1;
    }
    false
}

fn is_generated_alias_identifier(alias: &str) -> bool {
    let mut chars = alias.chars();
    match chars.next() {
        Some('t') => {}
        _ => return false,
    }
    let mut saw_digit = false;
    for ch in chars {
        if !ch.is_ascii_digit() {
            return false;
        }
        saw_digit = true;
    }
    saw_digit
}

fn is_alias_keyword_token(alias: &str) -> bool {
    matches!(
        alias.to_ascii_uppercase().as_str(),
        "SELECT" | "FROM" | "WHERE" | "GROUP" | "ORDER" | "JOIN" | "ON"
    )
}

fn apply_byte_replacements(sql: &str, mut replacements: Vec<(usize, usize, String)>) -> String {
    if replacements.is_empty() {
        return sql.to_string();
    }
    replacements.sort_by_key(|(start, _, _)| *start);
    replacements.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    let mut out = sql.to_string();
    for (start, end, replacement) in replacements.into_iter().rev() {
        if start < end && end <= out.len() {
            out.replace_range(start..end, &replacement);
        }
    }
    out
}

fn parse_subquery_alias_suffix(suffix: &str) -> Option<String> {
    let bytes = suffix.as_bytes();
    let mut i = skip_ascii_whitespace(bytes, 0);
    if let Some(as_end) = match_ascii_keyword_at(bytes, i, b"AS") {
        let after_as = skip_ascii_whitespace(bytes, as_end);
        if after_as == as_end {
            return None;
        }
        i = after_as;
    }

    let alias_start = i;
    let alias_end = consume_ascii_identifier(bytes, alias_start)?;
    i = skip_ascii_whitespace(bytes, alias_end);
    if i < bytes.len() && bytes[i] == b';' {
        i += 1;
        i = skip_ascii_whitespace(bytes, i);
    }
    if i != bytes.len() {
        return None;
    }
    Some(suffix[alias_start..alias_end].to_string())
}

fn extract_from_table_and_alias(sql: &str) -> Option<(String, String)> {
    let bytes = sql.as_bytes();
    let from_start = find_ascii_keyword(bytes, b"FROM", 0)?;
    let mut i = skip_ascii_whitespace(bytes, from_start + b"FROM".len());
    let table_start = i;
    i = consume_ascii_identifier(bytes, i)?;
    while i < bytes.len() && bytes[i] == b'.' {
        let next = consume_ascii_identifier(bytes, i + 1)?;
        i = next;
    }
    let table_name = sql[table_start..i].to_string();

    let mut alias = String::new();
    let after_table = skip_ascii_whitespace(bytes, i);
    if after_table > i {
        if let Some(as_end) = match_ascii_keyword_at(bytes, after_table, b"AS") {
            let alias_start = skip_ascii_whitespace(bytes, as_end);
            if alias_start > as_end {
                if let Some(alias_end) = consume_ascii_identifier(bytes, alias_start) {
                    alias = sql[alias_start..alias_end].to_string();
                }
            }
        } else if let Some(alias_end) = consume_ascii_identifier(bytes, after_table) {
            alias = sql[after_table..alias_end].to_string();
        }
    }

    Some((table_name, alias))
}

fn rewrite_double_quoted_identifiers(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'"' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let mut j = i + 1;
        let mut escaped = false;
        while j < bytes.len() {
            if bytes[j] == b'"' {
                if j + 1 < bytes.len() && bytes[j + 1] == b'"' {
                    escaped = true;
                    j += 2;
                    continue;
                }
                break;
            }
            j += 1;
        }
        if j >= bytes.len() {
            out.push('"');
            i += 1;
            continue;
        }

        if !escaped {
            let ident = &segment[i + 1..j];
            if is_simple_identifier(ident) && can_unquote_identifier_safely(ident) {
                out.push_str(ident);
                i = j + 1;
                continue;
            }
        }

        out.push_str(&segment[i..j + 1]);
        i = j + 1;
    }

    out
}

fn is_sql_keyword(token: &str) -> bool {
    matches!(
        token.to_ascii_uppercase().as_str(),
        "ALL"
            | "ALTER"
            | "AND"
            | "ANY"
            | "AS"
            | "ASC"
            | "BEGIN"
            | "BETWEEN"
            | "BOOLEAN"
            | "BY"
            | "CASE"
            | "CAST"
            | "CHECK"
            | "COLUMN"
            | "CONSTRAINT"
            | "CREATE"
            | "CROSS"
            | "DEFAULT"
            | "DELETE"
            | "DESC"
            | "DISTINCT"
            | "DROP"
            | "ELSE"
            | "END"
            | "EXCEPT"
            | "EXISTS"
            | "FALSE"
            | "FETCH"
            | "FOR"
            | "FOREIGN"
            | "FROM"
            | "FULL"
            | "GROUP"
            | "HAVING"
            | "IF"
            | "IN"
            | "INDEX"
            | "INNER"
            | "INSERT"
            | "INT"
            | "INTEGER"
            | "INTERSECT"
            | "INTO"
            | "IS"
            | "JOIN"
            | "KEY"
            | "LEFT"
            | "LIKE"
            | "LIMIT"
            | "NOT"
            | "NULL"
            | "OFFSET"
            | "ON"
            | "OR"
            | "ORDER"
            | "OUTER"
            | "OVER"
            | "PARTITION"
            | "PRIMARY"
            | "REFERENCES"
            | "RIGHT"
            | "SELECT"
            | "SET"
            | "TABLE"
            | "TEXT"
            | "THEN"
            | "TRUE"
            | "UNION"
            | "UNIQUE"
            | "UPDATE"
            | "USING"
            | "VALUES"
            | "VARCHAR"
            | "VIEW"
            | "WHEN"
            | "WHERE"
            | "WINDOW"
            | "WITH"
    )
}

fn fix_table_alias_keywords(sql: &str) -> String {
    let Some(decls) = collect_simple_table_alias_declarations(sql, Dialect::Generic) else {
        return sql.to_string();
    };

    let mut replacements = Vec::new();
    for decl in decls {
        if !decl.explicit_as || !is_alias_keyword_token(&decl.alias) {
            continue;
        }
        let clause = &sql[decl.keyword_start..decl.keyword_end];
        let table = &sql[decl.table_start..decl.table_end];
        replacements.push((
            decl.keyword_start,
            decl.alias_end,
            format!(
                "{clause} {table} AS alias_{}",
                decl.alias.to_ascii_lowercase()
            ),
        ));
    }

    apply_byte_replacements(sql, replacements)
}

fn fix_subquery_to_cte(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut i = skip_ascii_whitespace(bytes, 0);
    let Some(select_end) = match_ascii_keyword_at(bytes, i, b"SELECT") else {
        return sql.to_string();
    };
    i = skip_ascii_whitespace(bytes, select_end);
    if i == select_end || i >= bytes.len() || bytes[i] != b'*' {
        return sql.to_string();
    }
    i += 1;
    let from_start = skip_ascii_whitespace(bytes, i);
    if from_start == i {
        return sql.to_string();
    }
    let Some(from_end) = match_ascii_keyword_at(bytes, from_start, b"FROM") else {
        return sql.to_string();
    };
    let open_paren_idx = skip_ascii_whitespace(bytes, from_end);
    if open_paren_idx == from_end || open_paren_idx >= bytes.len() || bytes[open_paren_idx] != b'('
    {
        return sql.to_string();
    };

    let Some(close_paren_idx) = find_matching_parenthesis_outside_quotes(sql, open_paren_idx)
    else {
        return sql.to_string();
    };

    let subquery = sql[open_paren_idx + 1..close_paren_idx].trim();
    if !subquery.to_ascii_lowercase().starts_with("select") {
        return sql.to_string();
    }

    let suffix = &sql[close_paren_idx + 1..];
    let Some(alias) = parse_subquery_alias_suffix(suffix) else {
        return sql.to_string();
    };

    let mut rewritten = format!("WITH {alias} AS ({subquery}) SELECT * FROM {alias}");
    if suffix.trim_end().ends_with(';') {
        rewritten.push(';');
    }
    rewritten
}

fn find_matching_parenthesis_outside_quotes(sql: &str, open_paren_idx: usize) -> Option<usize> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Outside,
        SingleQuote,
        DoubleQuote,
        BacktickQuote,
        BracketQuote,
    }

    let bytes = sql.as_bytes();
    if open_paren_idx >= bytes.len() || bytes[open_paren_idx] != b'(' {
        return None;
    }

    let mut depth = 0usize;
    let mut mode = Mode::Outside;
    let mut i = open_paren_idx;

    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();

        match mode {
            Mode::Outside => {
                if b == b'\'' {
                    mode = Mode::SingleQuote;
                    i += 1;
                    continue;
                }
                if b == b'"' {
                    mode = Mode::DoubleQuote;
                    i += 1;
                    continue;
                }
                if b == b'`' {
                    mode = Mode::BacktickQuote;
                    i += 1;
                    continue;
                }
                if b == b'[' {
                    mode = Mode::BracketQuote;
                    i += 1;
                    continue;
                }
                if b == b'(' {
                    depth += 1;
                    i += 1;
                    continue;
                }
                if b == b')' {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                i += 1;
            }
            Mode::SingleQuote => {
                if b == b'\'' {
                    if next == Some(b'\'') {
                        i += 2;
                    } else {
                        mode = Mode::Outside;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            Mode::DoubleQuote => {
                if b == b'"' {
                    if next == Some(b'"') {
                        i += 2;
                    } else {
                        mode = Mode::Outside;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            Mode::BacktickQuote => {
                if b == b'`' {
                    if next == Some(b'`') {
                        i += 2;
                    } else {
                        mode = Mode::Outside;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            Mode::BracketQuote => {
                if b == b']' {
                    if next == Some(b']') {
                        i += 2;
                    } else {
                        mode = Mode::Outside;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
        }
    }

    None
}

fn fix_mixed_reference_qualification(sql: &str) -> String {
    let Some((table_name, alias)) = extract_from_table_and_alias(sql) else {
        return sql.to_string();
    };
    let prefix = if alias.is_empty() {
        table_name.rsplit('.').next().unwrap_or(&table_name)
    } else {
        alias.as_str()
    };
    if prefix.is_empty() {
        return sql.to_string();
    }

    let bytes = sql.as_bytes();
    let Some(select_start) = find_ascii_keyword(bytes, b"SELECT", 0) else {
        return sql.to_string();
    };
    let select_end = select_start + b"SELECT".len();
    let Some(from_start) = find_ascii_keyword(bytes, b"FROM", select_end) else {
        return sql.to_string();
    };

    let select_clause = &sql[select_end..from_start];
    let items: Vec<String> = select_clause
        .split(',')
        .map(|item| item.trim().to_string())
        .collect();
    let has_qualified = items
        .iter()
        .any(|item| is_simple_qualified_identifier(item));
    let has_unqualified = items.iter().any(|item| is_simple_identifier(item));
    if !(has_qualified && has_unqualified) {
        return sql.to_string();
    }

    let rewritten_items: Vec<String> = items
        .into_iter()
        .map(|item| {
            if is_simple_identifier(&item) {
                format!("{prefix}.{item}")
            } else {
                item
            }
        })
        .collect();
    let rewritten_clause = rewritten_items.join(", ");
    format!(
        "{}SELECT {rewritten_clause} FROM{}",
        &sql[..select_start],
        &sql[from_start + b"FROM".len()..]
    )
}

fn fix_quoted_literal_style(sql: &str, preferred_style: Cv010QuotedLiteralStyle) -> String {
    match preferred_style {
        Cv010QuotedLiteralStyle::DoubleQuotes => {
            // In most supported dialects, rewriting `'value'` -> `"value"` changes
            // semantics (string literal vs quoted identifier), so keep this no-op.
            sql.to_string()
        }
        Cv010QuotedLiteralStyle::Consistent | Cv010QuotedLiteralStyle::SingleQuotes => {
            // Safely reduce mixed quote-style findings by removing identifier quotes
            // only when unquoting preserves meaning.
            fix_references_quoting(sql)
        }
    }
}

fn fix_references_quoting(sql: &str) -> String {
    replace_outside_single_quotes(sql, rewrite_double_quoted_identifiers)
}

fn can_unquote_identifier_safely(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    let starts_ok = first.is_ascii_lowercase() || first == '_';
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');

    starts_ok && rest_ok && !is_sql_keyword(identifier)
}

/// Lowercase SQL keywords while preserving identifiers and string literals.
///
/// Only tokens that match `is_sql_keyword` are lowered; everything else is
/// kept as-is. Content inside quoted literals/identifiers is never touched.
fn fix_case_style_consistency(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if in_single {
            out.push(chars[i]);
            if chars[i] == '\'' {
                if i + 1 < chars.len() && chars[i + 1] == '\'' {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }

        if in_double {
            out.push(chars[i]);
            if chars[i] == '"' {
                if i + 1 < chars.len() && chars[i + 1] == '"' {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                in_double = false;
            }
            i += 1;
            continue;
        }

        if chars[i] == '\'' {
            in_single = true;
            out.push(chars[i]);
            i += 1;
            continue;
        }

        if chars[i] == '"' {
            in_double = true;
            out.push(chars[i]);
            i += 1;
            continue;
        }

        // Collect word tokens and lowercase only if they are SQL keywords
        if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            if is_sql_keyword(&token) {
                out.push_str(&token.to_ascii_lowercase());
            } else {
                out.push_str(&token);
            }
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }
    out
}

fn fix_tsql_procedure_begin_end(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(create_end) = match_ascii_keyword_at(bytes, i, b"CREATE") else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };
        let proc_start = skip_ascii_whitespace(bytes, create_end);
        if proc_start == create_end {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let Some(proc_end) = match_ascii_keyword_at(bytes, proc_start, b"PROC")
            .or_else(|| match_ascii_keyword_at(bytes, proc_start, b"PROCEDURE"))
        else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };

        let ident_start = skip_ascii_whitespace(bytes, proc_end);
        if ident_start == proc_end {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let Some(ident_end) = consume_ascii_identifier(bytes, ident_start) else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };

        let mut quote_start = ident_end;
        while quote_start < bytes.len() && is_ascii_whitespace_byte(bytes[quote_start]) {
            quote_start += 1;
        }
        if quote_start >= bytes.len() || bytes[quote_start] != b'\'' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        out.push_str("CREATE PROCEDURE ");
        out.push_str(&sql[ident_start..ident_end]);
        out.push_str(" BEGIN END");
        out.push_str(&sql[ident_end..quote_start + 1]);
        i = quote_start + 1;
    }

    out
}

fn fix_tsql_empty_batches(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'\n' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        let mut cursor = i;
        let mut batch_count = 0usize;
        while cursor < bytes.len() && bytes[cursor] == b'\n' {
            let mut go_start = cursor + 1;
            while go_start < bytes.len() && is_ascii_whitespace_non_newline_byte(bytes[go_start]) {
                go_start += 1;
            }
            let Some(go_end) = match_ascii_keyword_at(bytes, go_start, b"GO") else {
                break;
            };
            let mut after_go = go_end;
            while after_go < bytes.len() && is_ascii_whitespace_non_newline_byte(bytes[after_go]) {
                after_go += 1;
            }
            batch_count += 1;
            cursor = after_go;
        }

        if batch_count >= 2 {
            out.push_str("\nGO\n");
            i = cursor;
        } else {
            out.push('\n');
            i += 1;
        }
    }

    out
}

fn fix_trailing_newline(sql: &str) -> String {
    if sql.contains('\n') && !sql.ends_with('\n') {
        return format!("{sql}\n");
    }
    sql.to_string()
}

struct LocatedToken {
    token: Token,
    start: usize,
    end: usize,
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
        });
    }

    Some(out)
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

fn is_trivia_token(token: &Token) -> bool {
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

fn is_spacing_operator_token(token: &Token) -> bool {
    matches!(
        token,
        Token::Eq
            | Token::Neq
            | Token::Lt
            | Token::Gt
            | Token::LtEq
            | Token::GtEq
            | Token::Plus
            | Token::Minus
            | Token::DoubleEq
    )
}

fn collect_table_alias_idents_in_statement<F: FnMut(&Ident)>(
    statement: &Statement,
    visitor: &mut F,
) {
    match statement {
        Statement::Query(query) => collect_table_alias_idents_in_query(query, visitor),
        Statement::Insert(insert) => {
            if let Some(source) = &insert.source {
                collect_table_alias_idents_in_query(source, visitor);
            }
        }
        Statement::CreateView { query, .. } => collect_table_alias_idents_in_query(query, visitor),
        Statement::CreateTable(create) => {
            if let Some(query) = &create.query {
                collect_table_alias_idents_in_query(query, visitor);
            }
        }
        Statement::Merge { table, source, .. } => {
            collect_table_alias_idents_in_table_factor(table, visitor);
            collect_table_alias_idents_in_table_factor(source, visitor);
        }
        _ => {}
    }
}

fn collect_table_alias_idents_in_query<F: FnMut(&Ident)>(query: &Query, visitor: &mut F) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            collect_table_alias_idents_in_query(&cte.query, visitor);
        }
    }

    collect_table_alias_idents_in_set_expr(&query.body, visitor);
}

fn collect_table_alias_idents_in_set_expr<F: FnMut(&Ident)>(set_expr: &SetExpr, visitor: &mut F) {
    match set_expr {
        SetExpr::Select(select) => {
            for table in &select.from {
                collect_table_alias_idents_in_table_with_joins(table, visitor);
            }
        }
        SetExpr::Query(query) => collect_table_alias_idents_in_query(query, visitor),
        SetExpr::SetOperation { left, right, .. } => {
            collect_table_alias_idents_in_set_expr(left, visitor);
            collect_table_alias_idents_in_set_expr(right, visitor);
        }
        SetExpr::Insert(statement)
        | SetExpr::Update(statement)
        | SetExpr::Delete(statement)
        | SetExpr::Merge(statement) => collect_table_alias_idents_in_statement(statement, visitor),
        _ => {}
    }
}

fn collect_table_alias_idents_in_table_with_joins<F: FnMut(&Ident)>(
    table_with_joins: &TableWithJoins,
    visitor: &mut F,
) {
    collect_table_alias_idents_in_table_factor(&table_with_joins.relation, visitor);
    for join in &table_with_joins.joins {
        collect_table_alias_idents_in_table_factor(&join.relation, visitor);
    }
}

fn collect_table_alias_idents_in_table_factor<F: FnMut(&Ident)>(
    table_factor: &TableFactor,
    visitor: &mut F,
) {
    if let Some(alias) = table_factor_alias_ident(table_factor) {
        visitor(alias);
    }

    match table_factor {
        TableFactor::Derived { subquery, .. } => {
            collect_table_alias_idents_in_query(subquery, visitor);
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            collect_table_alias_idents_in_table_with_joins(table_with_joins, visitor);
        }
        TableFactor::Pivot { table, .. } | TableFactor::Unpivot { table, .. } => {
            collect_table_alias_idents_in_table_factor(table, visitor);
        }
        _ => {}
    }
}

fn fix_statement(stmt: &mut Statement, rule_filter: &RuleFilter) {
    match stmt {
        Statement::Query(query) => {
            if rule_filter.allows(issue_codes::LINT_CV_007) {
                unwrap_wrapper_queries(query);
            }
            fix_query(query, rule_filter);
        }
        Statement::Insert(insert) => {
            if let Some(source) = insert.source.as_mut() {
                fix_query(source, rule_filter);
            }
        }
        Statement::CreateView { query, .. } => fix_query(query, rule_filter),
        Statement::CreateTable(create) => {
            if let Some(query) = create.query.as_mut() {
                fix_query(query, rule_filter);
            }
        }
        _ => {}
    }
}

fn unwrap_wrapper_queries(query: &mut Query) {
    loop {
        if query.with.is_some()
            || query.order_by.is_some()
            || query.limit_clause.is_some()
            || query.fetch.is_some()
            || !query.locks.is_empty()
            || query.for_clause.is_some()
            || query.settings.is_some()
            || query.format_clause.is_some()
            || !query.pipe_operators.is_empty()
        {
            return;
        }

        let SetExpr::Query(inner) = query.body.as_ref() else {
            return;
        };

        *query = inner.as_ref().clone();
    }
}

fn fix_query(query: &mut Query, rule_filter: &RuleFilter) {
    if let Some(with) = query.with.as_mut() {
        for cte in &mut with.cte_tables {
            fix_query(&mut cte.query, rule_filter);
        }
    }

    let al07_rewrite =
        if rule_filter.allows(issue_codes::LINT_AL_007) && rule_filter.al007_force_enable {
            match query.body.as_ref() {
                SetExpr::Select(select) => single_table_alias_rewrite_plan(select),
                _ => None,
            }
        } else {
            None
        };

    fix_set_expr(query.body.as_mut(), rule_filter);
    rewrite_simple_derived_subqueries_to_ctes(query, rule_filter);

    if let Some(rewrite) = al07_rewrite.as_ref() {
        if let Some(order_by) = query.order_by.as_mut() {
            rewrite_alias_references_in_order_by(order_by, rewrite);
        }
        if let Some(limit_clause) = query.limit_clause.as_mut() {
            rewrite_alias_references_in_limit_clause(limit_clause, rewrite);
        }
        if let Some(fetch) = query.fetch.as_mut() {
            if let Some(quantity) = fetch.quantity.as_mut() {
                rewrite_expr_alias_qualifier(quantity, rewrite);
            }
        }
    }

    if let Some(order_by) = query.order_by.as_mut() {
        fix_order_by(order_by, rule_filter);
    }

    if let Some(limit_clause) = query.limit_clause.as_mut() {
        fix_limit_clause(limit_clause, rule_filter);
    }

    if let Some(fetch) = query.fetch.as_mut() {
        if let Some(quantity) = fetch.quantity.as_mut() {
            fix_expr(quantity, rule_filter);
        }
    }
}

fn fix_set_expr(body: &mut SetExpr, rule_filter: &RuleFilter) {
    match body {
        SetExpr::Select(select) => fix_select(select, rule_filter),
        SetExpr::Query(query) => fix_query(query, rule_filter),
        SetExpr::SetOperation {
            op,
            set_quantifier,
            left,
            right,
        } => {
            fix_set_expr(left, rule_filter);
            fix_set_expr(right, rule_filter);

            if rule_filter.allows(issue_codes::LINT_AM_002)
                && matches!(op, SetOperator::Union)
                && matches!(set_quantifier, SetQuantifier::None | SetQuantifier::ByName)
            {
                *set_quantifier = if matches!(set_quantifier, SetQuantifier::ByName) {
                    SetQuantifier::DistinctByName
                } else {
                    SetQuantifier::Distinct
                };
            }
        }
        SetExpr::Values(values) => {
            for row in &mut values.rows {
                for expr in row {
                    fix_expr(expr, rule_filter);
                }
            }
        }
        SetExpr::Insert(stmt)
        | SetExpr::Update(stmt)
        | SetExpr::Delete(stmt)
        | SetExpr::Merge(stmt) => fix_statement(stmt, rule_filter),
        _ => {}
    }
}

fn fix_select(select: &mut Select, rule_filter: &RuleFilter) {
    if rule_filter.allows(issue_codes::LINT_AM_001) && has_distinct_and_group_by(select) {
        select.distinct = None;
    }

    if rule_filter.allows(issue_codes::LINT_ST_008) {
        rewrite_distinct_parenthesized_projection(select);
    }

    if rule_filter.allows(issue_codes::LINT_AL_007) && rule_filter.al007_force_enable {
        let _ = apply_single_table_alias_rewrite(select);
    }

    for item in &mut select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                fix_expr(expr, rule_filter);
            }
            SelectItem::ExprWithAlias { expr, alias } => {
                fix_expr(expr, rule_filter);
                let remove_self_alias = rule_filter.allows(issue_codes::LINT_AL_009)
                    && expression_aliases_to_itself(expr, alias, rule_filter.al009_case_check);
                if remove_self_alias {
                    *item = SelectItem::UnnamedExpr(expr.clone());
                }
            }
            SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::Expr(expr), _) => {
                fix_expr(expr, rule_filter);
            }
            _ => {}
        }
    }

    if rule_filter.allows(issue_codes::LINT_ST_006) {
        if let Some(first_simple_idx) = select.projection.iter().position(is_simple_projection_item)
        {
            if first_simple_idx > 0 {
                let mut prefix = select
                    .projection
                    .drain(0..first_simple_idx)
                    .collect::<Vec<_>>();
                select.projection.append(&mut prefix);
            }
        }
    }

    let has_where_clause = select.selection.is_some();

    for table_with_joins in &mut select.from {
        if rule_filter.allows(issue_codes::LINT_CV_008) {
            rewrite_right_join_to_left(table_with_joins);
        }

        fix_table_factor(
            &mut table_with_joins.relation,
            rule_filter,
            has_where_clause,
        );

        let mut left_ref = table_factor_reference_name(&table_with_joins.relation);

        for join in &mut table_with_joins.joins {
            let right_ref = table_factor_reference_name(&join.relation);
            if rule_filter.allows(issue_codes::LINT_ST_007) {
                rewrite_using_join_constraint(
                    &mut join.join_operator,
                    left_ref.as_deref(),
                    right_ref.as_deref(),
                );
            }
            if rule_filter.allows(issue_codes::LINT_ST_009) {
                rewrite_join_condition_order(
                    &mut join.join_operator,
                    right_ref.as_deref(),
                    left_ref.as_deref(),
                );
            }

            fix_table_factor(&mut join.relation, rule_filter, has_where_clause);
            fix_join_operator(&mut join.join_operator, rule_filter, has_where_clause);

            if right_ref.is_some() {
                left_ref = right_ref;
            }
        }
    }

    if let Some(prewhere) = select.prewhere.as_mut() {
        fix_expr(prewhere, rule_filter);
    }

    if let Some(selection) = select.selection.as_mut() {
        fix_expr(selection, rule_filter);
    }

    if let Some(having) = select.having.as_mut() {
        fix_expr(having, rule_filter);
    }

    if let Some(qualify) = select.qualify.as_mut() {
        fix_expr(qualify, rule_filter);
    }

    if let GroupByExpr::Expressions(exprs, _) = &mut select.group_by {
        for expr in exprs {
            fix_expr(expr, rule_filter);
        }
    }

    for expr in &mut select.cluster_by {
        fix_expr(expr, rule_filter);
    }

    for expr in &mut select.distribute_by {
        fix_expr(expr, rule_filter);
    }

    for expr in &mut select.sort_by {
        fix_expr(&mut expr.expr, rule_filter);
    }

    for lateral_view in &mut select.lateral_views {
        fix_expr(&mut lateral_view.lateral_view, rule_filter);
    }

    if let Some(connect_by) = select.connect_by.as_mut() {
        fix_expr(&mut connect_by.condition, rule_filter);
        for relationship in &mut connect_by.relationships {
            fix_expr(relationship, rule_filter);
        }
    }
}

#[derive(Clone, Debug)]
struct TableAliasRewrite {
    alias: String,
    replacement_prefix: Vec<Ident>,
}

#[derive(Clone, Copy, Debug)]
struct NameRef<'a> {
    name: &'a str,
    quoted: bool,
}

fn single_table_alias_rewrite_plan(select: &Select) -> Option<TableAliasRewrite> {
    if select.from.len() != 1 || select_contains_subquery_expr(select) {
        return None;
    }

    let table_with_joins = select.from.first()?;
    if !table_with_joins.joins.is_empty() {
        return None;
    }

    let TableFactor::Table { name, alias, .. } = &table_with_joins.relation else {
        return None;
    };
    let alias = alias.as_ref()?;
    if !alias.columns.is_empty() {
        return None;
    }

    let alias_ident = &alias.name;
    if !is_simple_unquoted_identifier(alias_ident) || is_sql_keyword(&alias_ident.value) {
        return None;
    }

    let mut replacement_prefix = Vec::with_capacity(name.0.len());
    for part in &name.0 {
        let ident = part.as_ident()?;
        if !is_simple_unquoted_identifier(ident) {
            return None;
        }
        replacement_prefix.push(ident.clone());
    }
    if replacement_prefix.is_empty() {
        return None;
    }

    Some(TableAliasRewrite {
        alias: alias_ident.value.clone(),
        replacement_prefix,
    })
}

fn apply_single_table_alias_rewrite(select: &mut Select) -> Option<TableAliasRewrite> {
    let rewrite = single_table_alias_rewrite_plan(select)?;

    let table_with_joins = select.from.first_mut()?;
    let TableFactor::Table { alias, .. } = &mut table_with_joins.relation else {
        return None;
    };
    *alias = None;

    rewrite_alias_references_in_select(select, &rewrite);
    Some(rewrite)
}

fn is_simple_unquoted_identifier(ident: &Ident) -> bool {
    ident.quote_style.is_none()
        && ident.value.chars().enumerate().all(|(idx, ch)| {
            if idx == 0 {
                ch.is_ascii_alphabetic() || ch == '_'
            } else {
                ch.is_ascii_alphanumeric() || ch == '_'
            }
        })
}

fn select_contains_subquery_expr(select: &Select) -> bool {
    let projection_has_subquery = select.projection.iter().any(|item| match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
            expr_contains_subquery(expr)
        }
        SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::Expr(expr), _) => {
            expr_contains_subquery(expr)
        }
        _ => false,
    });
    if projection_has_subquery {
        return true;
    }

    for expr in [
        select.prewhere.as_ref(),
        select.selection.as_ref(),
        select.having.as_ref(),
        select.qualify.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if expr_contains_subquery(expr) {
            return true;
        }
    }

    if let GroupByExpr::Expressions(exprs, _) = &select.group_by {
        if exprs.iter().any(expr_contains_subquery) {
            return true;
        }
    }

    if select.cluster_by.iter().any(expr_contains_subquery)
        || select.distribute_by.iter().any(expr_contains_subquery)
        || select
            .sort_by
            .iter()
            .any(|expr| expr_contains_subquery(&expr.expr))
        || select
            .lateral_views
            .iter()
            .any(|lateral_view| expr_contains_subquery(&lateral_view.lateral_view))
    {
        return true;
    }

    if let Some(connect_by) = &select.connect_by {
        if expr_contains_subquery(&connect_by.condition)
            || connect_by.relationships.iter().any(expr_contains_subquery)
        {
            return true;
        }
    }

    false
}

fn expr_contains_subquery(expr: &Expr) -> bool {
    match expr {
        Expr::Subquery(_) | Expr::Exists { .. } => true,
        Expr::InSubquery {
            expr: inner,
            subquery,
            ..
        } => {
            let _ = subquery;
            expr_contains_subquery(inner)
        }
        Expr::BinaryOp { left, right, .. } => {
            expr_contains_subquery(left) || expr_contains_subquery(right)
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsUnknown(inner)
        | Expr::IsNotUnknown(inner)
        | Expr::Cast { expr: inner, .. } => expr_contains_subquery(inner),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            operand.as_deref().is_some_and(expr_contains_subquery)
                || conditions.iter().any(|case_when| {
                    expr_contains_subquery(&case_when.condition)
                        || expr_contains_subquery(&case_when.result)
                })
                || else_result.as_deref().is_some_and(expr_contains_subquery)
        }
        Expr::InList {
            expr: target, list, ..
        } => expr_contains_subquery(target) || list.iter().any(expr_contains_subquery),
        Expr::Between {
            expr: target,
            low,
            high,
            ..
        } => {
            expr_contains_subquery(target)
                || expr_contains_subquery(low)
                || expr_contains_subquery(high)
        }
        Expr::Tuple(items) => items.iter().any(expr_contains_subquery),
        Expr::Function(func) => function_contains_subquery(func),
        _ => false,
    }
}

fn function_contains_subquery(func: &Function) -> bool {
    let FunctionArguments::List(arg_list) = &func.args else {
        return false;
    };

    arg_list.args.iter().any(|arg| match arg {
        FunctionArg::Named { arg, .. }
        | FunctionArg::ExprNamed { arg, .. }
        | FunctionArg::Unnamed(arg) => match arg {
            FunctionArgExpr::Expr(expr) => expr_contains_subquery(expr),
            _ => false,
        },
    }) || arg_list.clauses.iter().any(|clause| match clause {
        FunctionArgumentClause::OrderBy(order_by_exprs) => order_by_exprs
            .iter()
            .any(|order_expr| expr_contains_subquery(&order_expr.expr)),
        FunctionArgumentClause::Limit(expr) => expr_contains_subquery(expr),
        _ => false,
    })
}

fn rewrite_alias_references_in_select(select: &mut Select, rewrite: &TableAliasRewrite) {
    for item in &mut select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                rewrite_expr_alias_qualifier(expr, rewrite);
            }
            SelectItem::QualifiedWildcard(kind, _) => match kind {
                SelectItemQualifiedWildcardKind::ObjectName(name) => {
                    rewrite_object_name_alias_qualifier(name, rewrite);
                }
                SelectItemQualifiedWildcardKind::Expr(expr) => {
                    rewrite_expr_alias_qualifier(expr, rewrite);
                }
            },
            _ => {}
        }
    }

    if let Some(prewhere) = select.prewhere.as_mut() {
        rewrite_expr_alias_qualifier(prewhere, rewrite);
    }
    if let Some(selection) = select.selection.as_mut() {
        rewrite_expr_alias_qualifier(selection, rewrite);
    }
    if let Some(having) = select.having.as_mut() {
        rewrite_expr_alias_qualifier(having, rewrite);
    }
    if let Some(qualify) = select.qualify.as_mut() {
        rewrite_expr_alias_qualifier(qualify, rewrite);
    }

    if let GroupByExpr::Expressions(exprs, _) = &mut select.group_by {
        for expr in exprs {
            rewrite_expr_alias_qualifier(expr, rewrite);
        }
    }

    for expr in &mut select.cluster_by {
        rewrite_expr_alias_qualifier(expr, rewrite);
    }
    for expr in &mut select.distribute_by {
        rewrite_expr_alias_qualifier(expr, rewrite);
    }
    for expr in &mut select.sort_by {
        rewrite_expr_alias_qualifier(&mut expr.expr, rewrite);
    }
    for lateral_view in &mut select.lateral_views {
        rewrite_expr_alias_qualifier(&mut lateral_view.lateral_view, rewrite);
    }
    if let Some(connect_by) = select.connect_by.as_mut() {
        rewrite_expr_alias_qualifier(&mut connect_by.condition, rewrite);
        for relationship in &mut connect_by.relationships {
            rewrite_expr_alias_qualifier(relationship, rewrite);
        }
    }
}

fn rewrite_alias_references_in_order_by(order_by: &mut OrderBy, rewrite: &TableAliasRewrite) {
    if let OrderByKind::Expressions(exprs) = &mut order_by.kind {
        for order_expr in exprs {
            rewrite_expr_alias_qualifier(&mut order_expr.expr, rewrite);
        }
    }

    if let Some(interpolate) = order_by.interpolate.as_mut() {
        if let Some(exprs) = interpolate.exprs.as_mut() {
            for expr in exprs {
                if let Some(inner) = expr.expr.as_mut() {
                    rewrite_expr_alias_qualifier(inner, rewrite);
                }
            }
        }
    }
}

fn rewrite_alias_references_in_limit_clause(
    limit_clause: &mut LimitClause,
    rewrite: &TableAliasRewrite,
) {
    match limit_clause {
        LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        } => {
            if let Some(limit) = limit {
                rewrite_expr_alias_qualifier(limit, rewrite);
            }
            if let Some(offset) = offset {
                rewrite_expr_alias_qualifier(&mut offset.value, rewrite);
            }
            for expr in limit_by {
                rewrite_expr_alias_qualifier(expr, rewrite);
            }
        }
        LimitClause::OffsetCommaLimit { offset, limit } => {
            rewrite_expr_alias_qualifier(offset, rewrite);
            rewrite_expr_alias_qualifier(limit, rewrite);
        }
    }
}

fn rewrite_expr_alias_qualifier(expr: &mut Expr, rewrite: &TableAliasRewrite) {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() >= 2 => {
            if ident_matches_alias(&parts[0], &rewrite.alias) {
                let mut rewritten = rewrite.replacement_prefix.clone();
                rewritten.extend(parts.iter().skip(1).cloned());
                *parts = rewritten;
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            rewrite_expr_alias_qualifier(left, rewrite);
            rewrite_expr_alias_qualifier(right, rewrite);
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsUnknown(inner)
        | Expr::IsNotUnknown(inner)
        | Expr::Cast { expr: inner, .. } => rewrite_expr_alias_qualifier(inner, rewrite),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand) = operand {
                rewrite_expr_alias_qualifier(operand, rewrite);
            }
            for case_when in conditions {
                rewrite_expr_alias_qualifier(&mut case_when.condition, rewrite);
                rewrite_expr_alias_qualifier(&mut case_when.result, rewrite);
            }
            if let Some(else_result) = else_result {
                rewrite_expr_alias_qualifier(else_result, rewrite);
            }
        }
        Expr::Function(func) => rewrite_function_alias_qualifier(func, rewrite),
        Expr::InSubquery {
            expr: target,
            subquery,
            ..
        } => {
            rewrite_expr_alias_qualifier(target, rewrite);
            let _ = subquery;
        }
        Expr::Between {
            expr: target,
            low,
            high,
            ..
        } => {
            rewrite_expr_alias_qualifier(target, rewrite);
            rewrite_expr_alias_qualifier(low, rewrite);
            rewrite_expr_alias_qualifier(high, rewrite);
        }
        Expr::InList {
            expr: target, list, ..
        } => {
            rewrite_expr_alias_qualifier(target, rewrite);
            for item in list {
                rewrite_expr_alias_qualifier(item, rewrite);
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                rewrite_expr_alias_qualifier(item, rewrite);
            }
        }
        _ => {}
    }
}

fn rewrite_function_alias_qualifier(func: &mut Function, rewrite: &TableAliasRewrite) {
    if let FunctionArguments::List(arg_list) = &mut func.args {
        for arg in &mut arg_list.args {
            rewrite_function_arg_alias_qualifier(arg, rewrite);
        }
        for clause in &mut arg_list.clauses {
            match clause {
                FunctionArgumentClause::OrderBy(order_by_exprs) => {
                    for order_by_expr in order_by_exprs {
                        rewrite_expr_alias_qualifier(&mut order_by_expr.expr, rewrite);
                    }
                }
                FunctionArgumentClause::Limit(expr) => rewrite_expr_alias_qualifier(expr, rewrite),
                _ => {}
            }
        }
    }

    if let Some(filter) = func.filter.as_mut() {
        rewrite_expr_alias_qualifier(filter, rewrite);
    }

    for order_expr in &mut func.within_group {
        rewrite_expr_alias_qualifier(&mut order_expr.expr, rewrite);
    }
}

fn rewrite_function_arg_alias_qualifier(arg: &mut FunctionArg, rewrite: &TableAliasRewrite) {
    match arg {
        FunctionArg::Named { arg, .. }
        | FunctionArg::ExprNamed { arg, .. }
        | FunctionArg::Unnamed(arg) => {
            if let FunctionArgExpr::Expr(expr) = arg {
                rewrite_expr_alias_qualifier(expr, rewrite);
            }
        }
    }
}

fn rewrite_object_name_alias_qualifier(object_name: &mut ObjectName, rewrite: &TableAliasRewrite) {
    let Some(first_ident) = object_name.0.first().and_then(|part| part.as_ident()) else {
        return;
    };
    if !ident_matches_alias(first_ident, &rewrite.alias) {
        return;
    }

    let mut rewritten = rewrite
        .replacement_prefix
        .iter()
        .cloned()
        .map(ObjectNamePart::Identifier)
        .collect::<Vec<_>>();
    rewritten.extend(object_name.0.iter().skip(1).cloned());
    object_name.0 = rewritten;
}

fn ident_matches_alias(ident: &Ident, alias: &str) -> bool {
    ident.value.eq_ignore_ascii_case(alias)
}

fn expression_aliases_to_itself(expr: &Expr, alias: &Ident, mode: Al009AliasCaseCheck) -> bool {
    let Some(source_name) = expression_name(expr) else {
        return false;
    };
    let alias_name = NameRef {
        name: alias.value.as_str(),
        quoted: alias.quote_style.is_some(),
    };
    names_match(source_name, alias_name, mode)
}

fn expression_name(expr: &Expr) -> Option<NameRef<'_>> {
    match expr {
        Expr::Identifier(identifier) => Some(NameRef {
            name: identifier.value.as_str(),
            quoted: identifier.quote_style.is_some(),
        }),
        Expr::CompoundIdentifier(parts) => parts.last().map(|part| NameRef {
            name: part.value.as_str(),
            quoted: part.quote_style.is_some(),
        }),
        Expr::Nested(inner) => expression_name(inner),
        _ => None,
    }
}

fn names_match(left: NameRef<'_>, right: NameRef<'_>, mode: Al009AliasCaseCheck) -> bool {
    match mode {
        Al009AliasCaseCheck::CaseInsensitive => left.name.eq_ignore_ascii_case(right.name),
        Al009AliasCaseCheck::CaseSensitive => left.name == right.name,
        Al009AliasCaseCheck::Dialect => {
            if left.quoted || right.quoted {
                left.name == right.name
            } else {
                left.name.eq_ignore_ascii_case(right.name)
            }
        }
        Al009AliasCaseCheck::QuotedCsNakedUpper | Al009AliasCaseCheck::QuotedCsNakedLower => {
            normalize_name_for_mode(left, mode) == normalize_name_for_mode(right, mode)
        }
    }
}

fn normalize_name_for_mode(name_ref: NameRef<'_>, mode: Al009AliasCaseCheck) -> String {
    match mode {
        Al009AliasCaseCheck::QuotedCsNakedUpper => {
            if name_ref.quoted {
                name_ref.name.to_string()
            } else {
                name_ref.name.to_ascii_uppercase()
            }
        }
        Al009AliasCaseCheck::QuotedCsNakedLower => {
            if name_ref.quoted {
                name_ref.name.to_string()
            } else {
                name_ref.name.to_ascii_lowercase()
            }
        }
        _ => name_ref.name.to_string(),
    }
}

fn rewrite_distinct_parenthesized_projection(select: &mut Select) {
    if !matches!(select.distinct, Some(Distinct::Distinct)) {
        return;
    }

    if select.projection.len() != 1 {
        return;
    }

    if let SelectItem::UnnamedExpr(expr) = &mut select.projection[0] {
        if let Expr::Nested(inner) = expr {
            *expr = inner.as_ref().clone();
        }
    }
}

fn has_distinct_and_group_by(select: &Select) -> bool {
    let has_distinct = matches!(
        select.distinct,
        Some(Distinct::Distinct) | Some(Distinct::On(_))
    );
    let has_group_by = match &select.group_by {
        GroupByExpr::All(_) => true,
        GroupByExpr::Expressions(exprs, _) => !exprs.is_empty(),
    };
    has_distinct && has_group_by
}

fn rewrite_simple_derived_subqueries_to_ctes(query: &mut Query, rule_filter: &RuleFilter) {
    if !rule_filter.allows(issue_codes::LINT_ST_005) {
        return;
    }

    let SetExpr::Select(select) = query.body.as_mut() else {
        return;
    };

    let outer_source_names = select_source_names_upper(select);
    let mut used_cte_names: HashSet<String> = query
        .with
        .as_ref()
        .map(|with| {
            with.cte_tables
                .iter()
                .map(|cte| cte.alias.name.value.to_ascii_uppercase())
                .collect()
        })
        .unwrap_or_default();
    used_cte_names.extend(outer_source_names.iter().cloned());

    let mut new_ctes = Vec::new();

    for table_with_joins in &mut select.from {
        if rule_filter.st005_forbid_subquery_in.forbid_from() {
            if let Some(cte) = rewrite_derived_table_factor_to_cte(
                &mut table_with_joins.relation,
                &outer_source_names,
                &mut used_cte_names,
            ) {
                new_ctes.push(cte);
            }
        }

        if rule_filter.st005_forbid_subquery_in.forbid_join() {
            for join in &mut table_with_joins.joins {
                if let Some(cte) = rewrite_derived_table_factor_to_cte(
                    &mut join.relation,
                    &outer_source_names,
                    &mut used_cte_names,
                ) {
                    new_ctes.push(cte);
                }
            }
        }
    }

    if new_ctes.is_empty() {
        return;
    }

    let with = query.with.get_or_insert_with(|| With {
        with_token: AttachedToken::empty(),
        recursive: false,
        cte_tables: Vec::new(),
    });
    with.cte_tables.extend(new_ctes);
}

fn rewrite_derived_table_factor_to_cte(
    relation: &mut TableFactor,
    outer_source_names: &HashSet<String>,
    used_cte_names: &mut HashSet<String>,
) -> Option<Cte> {
    let (lateral, subquery, alias) = match relation {
        TableFactor::Derived {
            lateral,
            subquery,
            alias,
        } => (lateral, subquery, alias),
        _ => return None,
    };

    if *lateral {
        return None;
    }

    // Keep this rewrite conservative: only SELECT subqueries that do not
    // appear to reference outer sources.
    if !matches!(subquery.body.as_ref(), SetExpr::Select(_))
        || query_text_references_outer_sources(subquery, outer_source_names)
    {
        return None;
    }

    let cte_alias = alias.clone().unwrap_or_else(|| TableAlias {
        name: Ident::new(next_generated_cte_name(used_cte_names)),
        columns: Vec::new(),
    });
    let cte_name_ident = cte_alias.name.clone();
    let cte_name_upper = cte_name_ident.value.to_ascii_uppercase();
    used_cte_names.insert(cte_name_upper);

    let cte = Cte {
        alias: cte_alias,
        query: subquery.clone(),
        from: None,
        materialized: None,
        closing_paren_token: AttachedToken::empty(),
    };

    *relation = TableFactor::Table {
        name: vec![cte_name_ident].into(),
        alias: None,
        args: None,
        with_hints: Vec::new(),
        version: None,
        with_ordinality: false,
        partitions: Vec::new(),
        json_path: None,
        sample: None,
        index_hints: Vec::new(),
    };

    Some(cte)
}

fn next_generated_cte_name(used_cte_names: &HashSet<String>) -> String {
    let mut index = 1usize;
    loop {
        let candidate = format!("cte_subquery_{index}");
        if !used_cte_names.contains(&candidate.to_ascii_uppercase()) {
            return candidate;
        }
        index += 1;
    }
}

fn query_text_references_outer_sources(
    query: &Query,
    outer_source_names: &HashSet<String>,
) -> bool {
    if outer_source_names.is_empty() {
        return false;
    }

    let rendered_upper = query.to_string().to_ascii_uppercase();
    outer_source_names
        .iter()
        .any(|name| rendered_upper.contains(&format!("{name}.")))
}

fn select_source_names_upper(select: &Select) -> HashSet<String> {
    let mut names = HashSet::new();
    for table in &select.from {
        collect_source_names_from_table_factor(&table.relation, &mut names);
        for join in &table.joins {
            collect_source_names_from_table_factor(&join.relation, &mut names);
        }
    }
    names
}

fn collect_source_names_from_table_factor(relation: &TableFactor, names: &mut HashSet<String>) {
    match relation {
        TableFactor::Table { name, alias, .. } => {
            if let Some(last) = name.0.last().and_then(|part| part.as_ident()) {
                names.insert(last.value.to_ascii_uppercase());
            }
            if let Some(alias) = alias {
                names.insert(alias.name.value.to_ascii_uppercase());
            }
        }
        TableFactor::Derived { alias, .. }
        | TableFactor::TableFunction { alias, .. }
        | TableFactor::Function { alias, .. }
        | TableFactor::UNNEST { alias, .. }
        | TableFactor::JsonTable { alias, .. }
        | TableFactor::OpenJsonTable { alias, .. }
        | TableFactor::NestedJoin { alias, .. }
        | TableFactor::Pivot { alias, .. }
        | TableFactor::Unpivot { alias, .. } => {
            if let Some(alias) = alias {
                names.insert(alias.name.value.to_ascii_uppercase());
            }
        }
        _ => {}
    }
}

fn rewrite_right_join_to_left(table_with_joins: &mut TableWithJoins) {
    while let Some(index) = table_with_joins
        .joins
        .iter()
        .position(|join| rewritable_right_join(&join.join_operator))
    {
        rewrite_right_join_at_index(table_with_joins, index);
    }
}

fn rewrite_right_join_at_index(table_with_joins: &mut TableWithJoins, index: usize) {
    let mut suffix = table_with_joins.joins.split_off(index);
    let mut join = suffix.remove(0);

    let old_operator = std::mem::replace(
        &mut join.join_operator,
        JoinOperator::CrossJoin(JoinConstraint::None),
    );
    let Some(new_operator) = rewritten_left_join_operator(old_operator) else {
        table_with_joins.joins.push(join);
        table_with_joins.joins.append(&mut suffix);
        return;
    };

    let previous_relation = std::mem::replace(&mut table_with_joins.relation, join.relation);
    let prefix_joins = std::mem::take(&mut table_with_joins.joins);

    join.relation = if prefix_joins.is_empty() {
        previous_relation
    } else {
        TableFactor::NestedJoin {
            table_with_joins: Box::new(TableWithJoins {
                relation: previous_relation,
                joins: prefix_joins,
            }),
            alias: None,
        }
    };
    join.join_operator = new_operator;

    table_with_joins.joins.push(join);
    table_with_joins.joins.append(&mut suffix);
}

fn rewritable_right_join(operator: &JoinOperator) -> bool {
    matches!(
        operator,
        JoinOperator::Right(_)
            | JoinOperator::RightOuter(_)
            | JoinOperator::RightSemi(_)
            | JoinOperator::RightAnti(_)
    )
}

fn rewritten_left_join_operator(operator: JoinOperator) -> Option<JoinOperator> {
    match operator {
        JoinOperator::Right(constraint) => Some(JoinOperator::Left(constraint)),
        JoinOperator::RightOuter(constraint) => Some(JoinOperator::LeftOuter(constraint)),
        JoinOperator::RightSemi(constraint) => Some(JoinOperator::LeftSemi(constraint)),
        JoinOperator::RightAnti(constraint) => Some(JoinOperator::LeftAnti(constraint)),
        _ => None,
    }
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

fn table_factor_alias_ident(relation: &TableFactor) -> Option<&Ident> {
    let alias = match relation {
        TableFactor::Table { alias, .. }
        | TableFactor::Derived { alias, .. }
        | TableFactor::TableFunction { alias, .. }
        | TableFactor::Function { alias, .. }
        | TableFactor::UNNEST { alias, .. }
        | TableFactor::JsonTable { alias, .. }
        | TableFactor::OpenJsonTable { alias, .. }
        | TableFactor::NestedJoin { alias, .. }
        | TableFactor::Pivot { alias, .. }
        | TableFactor::Unpivot { alias, .. } => alias.as_ref(),
        _ => None,
    }?;

    Some(&alias.name)
}

fn table_factor_reference_name(relation: &TableFactor) -> Option<String> {
    match relation {
        TableFactor::Table { name, alias, .. } => {
            if let Some(alias) = alias {
                Some(alias.name.value.clone())
            } else {
                name.0
                    .last()
                    .and_then(|part| part.as_ident())
                    .map(|ident| ident.value.clone())
            }
        }
        _ => None,
    }
}

fn rewrite_using_join_constraint(
    join_operator: &mut JoinOperator,
    left_ref: Option<&str>,
    right_ref: Option<&str>,
) {
    let (Some(left_ref), Some(right_ref)) = (left_ref, right_ref) else {
        return;
    };

    let Some(constraint) = join_constraint_mut(join_operator) else {
        return;
    };

    let JoinConstraint::Using(columns) = constraint else {
        return;
    };

    if columns.is_empty() {
        return;
    }

    let mut combined: Option<Expr> = None;
    for object_name in columns.iter() {
        let Some(column_ident) = object_name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .cloned()
        else {
            continue;
        };

        let equality = Expr::BinaryOp {
            left: Box::new(Expr::CompoundIdentifier(vec![
                Ident::new(left_ref),
                column_ident.clone(),
            ])),
            op: BinaryOperator::Eq,
            right: Box::new(Expr::CompoundIdentifier(vec![
                Ident::new(right_ref),
                column_ident,
            ])),
        };

        combined = Some(match combined {
            Some(prev) => Expr::BinaryOp {
                left: Box::new(prev),
                op: BinaryOperator::And,
                right: Box::new(equality),
            },
            None => equality,
        });
    }

    if let Some(on_expr) = combined {
        *constraint = JoinConstraint::On(on_expr);
    }
}

fn rewrite_join_condition_order(
    join_operator: &mut JoinOperator,
    current_source: Option<&str>,
    previous_source: Option<&str>,
) {
    let (Some(current_source), Some(previous_source)) = (current_source, previous_source) else {
        return;
    };

    let current_source = current_source.to_ascii_uppercase();
    let previous_source = previous_source.to_ascii_uppercase();

    let Some(constraint) = join_constraint_mut(join_operator) else {
        return;
    };

    let JoinConstraint::On(on_expr) = constraint else {
        return;
    };

    rewrite_reversed_join_pairs(on_expr, &current_source, &previous_source);
}

fn rewrite_reversed_join_pairs(expr: &mut Expr, current_source: &str, previous_source: &str) {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            if *op == BinaryOperator::Eq {
                let left_prefix = expr_qualified_prefix(left);
                let right_prefix = expr_qualified_prefix(right);
                if left_prefix.as_deref() == Some(current_source)
                    && right_prefix.as_deref() == Some(previous_source)
                {
                    std::mem::swap(left, right);
                }
            }

            rewrite_reversed_join_pairs(left, current_source, previous_source);
            rewrite_reversed_join_pairs(right, current_source, previous_source);
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsUnknown(inner)
        | Expr::IsNotUnknown(inner)
        | Expr::Cast { expr: inner, .. } => {
            rewrite_reversed_join_pairs(inner, current_source, previous_source)
        }
        Expr::InList {
            expr: target, list, ..
        } => {
            rewrite_reversed_join_pairs(target, current_source, previous_source);
            for item in list {
                rewrite_reversed_join_pairs(item, current_source, previous_source);
            }
        }
        Expr::Between {
            expr: target,
            low,
            high,
            ..
        } => {
            rewrite_reversed_join_pairs(target, current_source, previous_source);
            rewrite_reversed_join_pairs(low, current_source, previous_source);
            rewrite_reversed_join_pairs(high, current_source, previous_source);
        }
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand) = operand {
                rewrite_reversed_join_pairs(operand, current_source, previous_source);
            }
            for case_when in conditions {
                rewrite_reversed_join_pairs(
                    &mut case_when.condition,
                    current_source,
                    previous_source,
                );
                rewrite_reversed_join_pairs(&mut case_when.result, current_source, previous_source);
            }
            if let Some(else_result) = else_result {
                rewrite_reversed_join_pairs(else_result, current_source, previous_source);
            }
        }
        _ => {}
    }
}

fn expr_qualified_prefix(expr: &Expr) -> Option<String> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() > 1 => {
            parts.first().map(|ident| ident.value.to_ascii_uppercase())
        }
        Expr::Nested(inner)
        | Expr::UnaryOp { expr: inner, .. }
        | Expr::Cast { expr: inner, .. } => expr_qualified_prefix(inner),
        _ => None,
    }
}

fn fix_table_factor(relation: &mut TableFactor, rule_filter: &RuleFilter, has_where_clause: bool) {
    match relation {
        TableFactor::Table {
            args, with_hints, ..
        } => {
            if let Some(args) = args {
                for arg in &mut args.args {
                    fix_function_arg(arg, rule_filter);
                }
            }
            for hint in with_hints {
                fix_expr(hint, rule_filter);
            }
        }
        TableFactor::Derived { subquery, .. } => fix_query(subquery, rule_filter),
        TableFactor::TableFunction { expr, .. } => fix_expr(expr, rule_filter),
        TableFactor::Function { args, .. } => {
            for arg in args {
                fix_function_arg(arg, rule_filter);
            }
        }
        TableFactor::UNNEST { array_exprs, .. } => {
            for expr in array_exprs {
                fix_expr(expr, rule_filter);
            }
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            if rule_filter.allows(issue_codes::LINT_CV_008) {
                rewrite_right_join_to_left(table_with_joins);
            }

            fix_table_factor(
                &mut table_with_joins.relation,
                rule_filter,
                has_where_clause,
            );

            let mut left_ref = table_factor_reference_name(&table_with_joins.relation);

            for join in &mut table_with_joins.joins {
                let right_ref = table_factor_reference_name(&join.relation);
                if rule_filter.allows(issue_codes::LINT_ST_007) {
                    rewrite_using_join_constraint(
                        &mut join.join_operator,
                        left_ref.as_deref(),
                        right_ref.as_deref(),
                    );
                }
                if rule_filter.allows(issue_codes::LINT_ST_009) {
                    rewrite_join_condition_order(
                        &mut join.join_operator,
                        right_ref.as_deref(),
                        left_ref.as_deref(),
                    );
                }

                fix_table_factor(&mut join.relation, rule_filter, has_where_clause);
                fix_join_operator(&mut join.join_operator, rule_filter, has_where_clause);

                if right_ref.is_some() {
                    left_ref = right_ref;
                }
            }
        }
        TableFactor::Pivot {
            table,
            aggregate_functions,
            value_column,
            default_on_null,
            ..
        } => {
            fix_table_factor(table, rule_filter, has_where_clause);
            for func in aggregate_functions {
                fix_expr(&mut func.expr, rule_filter);
            }
            for expr in value_column {
                fix_expr(expr, rule_filter);
            }
            if let Some(expr) = default_on_null {
                fix_expr(expr, rule_filter);
            }
        }
        TableFactor::Unpivot {
            table,
            value,
            columns,
            ..
        } => {
            fix_table_factor(table, rule_filter, has_where_clause);
            fix_expr(value, rule_filter);
            for column in columns {
                fix_expr(&mut column.expr, rule_filter);
            }
        }
        TableFactor::JsonTable { json_expr, .. } => fix_expr(json_expr, rule_filter),
        TableFactor::OpenJsonTable { json_expr, .. } => fix_expr(json_expr, rule_filter),
        _ => {}
    }
}

fn fix_join_operator(op: &mut JoinOperator, rule_filter: &RuleFilter, has_where_clause: bool) {
    match op {
        JoinOperator::Join(constraint)
        | JoinOperator::Inner(constraint)
        | JoinOperator::Left(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::Right(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::FullOuter(constraint)
        | JoinOperator::CrossJoin(constraint)
        | JoinOperator::Semi(constraint)
        | JoinOperator::LeftSemi(constraint)
        | JoinOperator::RightSemi(constraint)
        | JoinOperator::Anti(constraint)
        | JoinOperator::LeftAnti(constraint)
        | JoinOperator::RightAnti(constraint)
        | JoinOperator::StraightJoin(constraint) => fix_join_constraint(constraint, rule_filter),
        JoinOperator::AsOf {
            match_condition,
            constraint,
        } => {
            fix_expr(match_condition, rule_filter);
            fix_join_constraint(constraint, rule_filter);
        }
        JoinOperator::CrossApply | JoinOperator::OuterApply => {}
    }

    if rule_filter.allows(issue_codes::LINT_AM_008)
        && !has_where_clause
        && operator_requires_join_condition(op)
        && !join_constraint_is_explicit(op)
    {
        *op = JoinOperator::CrossJoin(JoinConstraint::None);
        return;
    }

    if rule_filter.allows(issue_codes::LINT_AM_005) {
        match rule_filter.am005_mode {
            Am005QualifyMode::Inner => {
                if let JoinOperator::Join(constraint) = op {
                    *op = JoinOperator::Inner(constraint.clone());
                }
            }
            Am005QualifyMode::Outer => qualify_outer_join_keyword(op),
            Am005QualifyMode::Both => {
                if let JoinOperator::Join(constraint) = op {
                    *op = JoinOperator::Inner(constraint.clone());
                } else {
                    qualify_outer_join_keyword(op);
                }
            }
        }
    }
}

fn qualify_outer_join_keyword(op: &mut JoinOperator) {
    match op {
        JoinOperator::Left(constraint) => {
            *op = JoinOperator::LeftOuter(constraint.clone());
        }
        JoinOperator::Right(constraint) => {
            *op = JoinOperator::RightOuter(constraint.clone());
        }
        JoinOperator::FullOuter(_) => {}
        _ => {}
    }
}

fn operator_requires_join_condition(join_operator: &JoinOperator) -> bool {
    matches!(
        join_operator,
        JoinOperator::Join(_)
            | JoinOperator::Inner(_)
            | JoinOperator::Left(_)
            | JoinOperator::LeftOuter(_)
            | JoinOperator::Right(_)
            | JoinOperator::RightOuter(_)
            | JoinOperator::FullOuter(_)
            | JoinOperator::StraightJoin(_)
    )
}

fn join_constraint_is_explicit(join_operator: &JoinOperator) -> bool {
    let Some(constraint) = join_constraint(join_operator) else {
        return false;
    };

    matches!(
        constraint,
        JoinConstraint::On(_) | JoinConstraint::Using(_) | JoinConstraint::Natural
    )
}

fn join_constraint_mut(join_operator: &mut JoinOperator) -> Option<&mut JoinConstraint> {
    match join_operator {
        JoinOperator::Join(constraint)
        | JoinOperator::Inner(constraint)
        | JoinOperator::Left(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::Right(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::FullOuter(constraint)
        | JoinOperator::CrossJoin(constraint)
        | JoinOperator::Semi(constraint)
        | JoinOperator::LeftSemi(constraint)
        | JoinOperator::RightSemi(constraint)
        | JoinOperator::Anti(constraint)
        | JoinOperator::LeftAnti(constraint)
        | JoinOperator::RightAnti(constraint)
        | JoinOperator::StraightJoin(constraint) => Some(constraint),
        JoinOperator::AsOf { constraint, .. } => Some(constraint),
        JoinOperator::CrossApply | JoinOperator::OuterApply => None,
    }
}

fn join_constraint(join_operator: &JoinOperator) -> Option<&JoinConstraint> {
    match join_operator {
        JoinOperator::Join(constraint)
        | JoinOperator::Inner(constraint)
        | JoinOperator::Left(constraint)
        | JoinOperator::LeftOuter(constraint)
        | JoinOperator::Right(constraint)
        | JoinOperator::RightOuter(constraint)
        | JoinOperator::FullOuter(constraint)
        | JoinOperator::CrossJoin(constraint)
        | JoinOperator::Semi(constraint)
        | JoinOperator::LeftSemi(constraint)
        | JoinOperator::RightSemi(constraint)
        | JoinOperator::Anti(constraint)
        | JoinOperator::LeftAnti(constraint)
        | JoinOperator::RightAnti(constraint)
        | JoinOperator::StraightJoin(constraint) => Some(constraint),
        JoinOperator::AsOf { constraint, .. } => Some(constraint),
        JoinOperator::CrossApply | JoinOperator::OuterApply => None,
    }
}

fn fix_join_constraint(constraint: &mut JoinConstraint, rule_filter: &RuleFilter) {
    if let JoinConstraint::On(expr) = constraint {
        fix_expr(expr, rule_filter);
    }
}

fn fix_order_by(order_by: &mut OrderBy, rule_filter: &RuleFilter) {
    if let OrderByKind::Expressions(exprs) = &mut order_by.kind {
        for order_expr in exprs.iter_mut() {
            fix_expr(&mut order_expr.expr, rule_filter);
        }

        if rule_filter.allows(issue_codes::LINT_AM_003) {
            let has_explicit = exprs
                .iter()
                .any(|order_expr| order_expr.options.asc.is_some());
            let has_implicit = exprs
                .iter()
                .any(|order_expr| order_expr.options.asc.is_none());

            if has_explicit && has_implicit {
                for order_expr in exprs.iter_mut() {
                    if order_expr.options.asc.is_none() {
                        order_expr.options.asc = Some(true);
                    }
                }
            }
        }
    }

    if let Some(interpolate) = order_by.interpolate.as_mut() {
        if let Some(exprs) = interpolate.exprs.as_mut() {
            for expr in exprs {
                if let Some(inner) = expr.expr.as_mut() {
                    fix_expr(inner, rule_filter);
                }
            }
        }
    }
}

fn fix_limit_clause(limit_clause: &mut LimitClause, rule_filter: &RuleFilter) {
    match limit_clause {
        LimitClause::LimitOffset {
            limit,
            offset,
            limit_by,
        } => {
            if let Some(limit) = limit {
                fix_expr(limit, rule_filter);
            }
            if let Some(offset) = offset {
                fix_expr(&mut offset.value, rule_filter);
            }
            for expr in limit_by {
                fix_expr(expr, rule_filter);
            }
        }
        LimitClause::OffsetCommaLimit { offset, limit } => {
            fix_expr(offset, rule_filter);
            fix_expr(limit, rule_filter);
        }
    }
}

fn fix_expr(expr: &mut Expr, rule_filter: &RuleFilter) {
    match expr {
        Expr::BinaryOp { left, right, .. } => {
            fix_expr(left, rule_filter);
            fix_expr(right, rule_filter);
        }
        Expr::UnaryOp { expr: inner, .. }
        | Expr::Nested(inner)
        | Expr::IsNull(inner)
        | Expr::IsNotNull(inner)
        | Expr::IsTrue(inner)
        | Expr::IsNotTrue(inner)
        | Expr::IsFalse(inner)
        | Expr::IsNotFalse(inner)
        | Expr::IsUnknown(inner)
        | Expr::IsNotUnknown(inner) => fix_expr(inner, rule_filter),
        Expr::Case {
            operand,
            conditions,
            else_result,
            ..
        } => {
            if let Some(operand) = operand.as_mut() {
                fix_expr(operand, rule_filter);
            }
            for case_when in conditions {
                fix_expr(&mut case_when.condition, rule_filter);
                fix_expr(&mut case_when.result, rule_filter);
            }
            if let Some(else_result) = else_result.as_mut() {
                fix_expr(else_result, rule_filter);
            }
        }
        Expr::Function(func) => fix_function(func, rule_filter),
        Expr::Cast { expr: inner, .. } => fix_expr(inner, rule_filter),
        Expr::InSubquery {
            expr: inner,
            subquery,
            ..
        } => {
            fix_expr(inner, rule_filter);
            fix_query(subquery, rule_filter);
        }
        Expr::Subquery(subquery) | Expr::Exists { subquery, .. } => {
            fix_query(subquery, rule_filter)
        }
        Expr::Between {
            expr: target,
            low,
            high,
            ..
        } => {
            fix_expr(target, rule_filter);
            fix_expr(low, rule_filter);
            fix_expr(high, rule_filter);
        }
        Expr::InList {
            expr: target, list, ..
        } => {
            fix_expr(target, rule_filter);
            for item in list {
                fix_expr(item, rule_filter);
            }
        }
        Expr::Tuple(items) => {
            for item in items {
                fix_expr(item, rule_filter);
            }
        }
        _ => {}
    }

    if rule_filter.allows(issue_codes::LINT_CV_001) {
        if let Some(rewritten) = null_comparison_rewrite(expr) {
            *expr = rewritten;
            return;
        }
    }

    if rule_filter.allows(issue_codes::LINT_CV_011) {
        rewrite_cast_style(expr, rule_filter.cv011_style);
    }

    if rule_filter.allows(issue_codes::LINT_ST_004) {
        if let Some(rewritten) = nested_case_rewrite(expr) {
            *expr = rewritten;
        }
    }

    if rule_filter.allows(issue_codes::LINT_ST_002) {
        if let Some(rewritten) = simple_case_rewrite(expr) {
            *expr = rewritten;
        }
    }

    if let Expr::Case {
        else_result: Some(else_result),
        ..
    } = expr
    {
        if rule_filter.allows(issue_codes::LINT_ST_001) && lint_helpers::is_null_expr(else_result) {
            if let Expr::Case { else_result, .. } = expr {
                *else_result = None;
            }
        }
    }
}

fn rewrite_cast_style(expr: &mut Expr, preferred_style: Cv011CastingStyle) {
    let Expr::Cast {
        kind,
        expr: inner,
        format,
        ..
    } = expr
    else {
        return;
    };

    match preferred_style {
        Cv011CastingStyle::Cast | Cv011CastingStyle::Consistent => {
            if *kind == CastKind::DoubleColon {
                *kind = CastKind::Cast;
            }
        }
        Cv011CastingStyle::Shorthand => {
            if *kind == CastKind::Cast
                && format.is_none()
                && cast_expr_can_use_shorthand(inner.as_ref())
            {
                *kind = CastKind::DoubleColon;
            }
        }
        Cv011CastingStyle::Convert => {}
    }
}

fn cast_expr_can_use_shorthand(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Identifier(_)
            | Expr::CompoundIdentifier(_)
            | Expr::Value(_)
            | Expr::Function(_)
            | Expr::Cast { .. }
            | Expr::Nested(_)
            | Expr::TypedString { .. }
    )
}

fn fix_function(func: &mut Function, rule_filter: &RuleFilter) {
    if let FunctionArguments::List(arg_list) = &mut func.args {
        for arg in &mut arg_list.args {
            fix_function_arg(arg, rule_filter);
        }
        for clause in &mut arg_list.clauses {
            match clause {
                FunctionArgumentClause::OrderBy(order_by_exprs) => {
                    for order_by_expr in order_by_exprs {
                        fix_expr(&mut order_by_expr.expr, rule_filter);
                    }
                }
                FunctionArgumentClause::Limit(expr) => fix_expr(expr, rule_filter),
                _ => {}
            }
        }
    }

    if let Some(filter) = func.filter.as_mut() {
        fix_expr(filter, rule_filter);
    }

    for order_expr in &mut func.within_group {
        fix_expr(&mut order_expr.expr, rule_filter);
    }

    if rule_filter.allows(issue_codes::LINT_CV_002) {
        let function_name_upper = func.name.to_string().to_ascii_uppercase();
        if function_name_upper == "IFNULL" || function_name_upper == "NVL" {
            func.name = vec![Ident::new("COALESCE")].into();
        }
    }

    if rule_filter.allows(issue_codes::LINT_CV_004) && is_count_rowcount_numeric_literal(func) {
        if let FunctionArguments::List(arg_list) = &mut func.args {
            arg_list.args[0] = FunctionArg::Unnamed(FunctionArgExpr::Wildcard);
        }
    }
}

fn fix_function_arg(arg: &mut FunctionArg, rule_filter: &RuleFilter) {
    match arg {
        FunctionArg::Named { arg, .. }
        | FunctionArg::ExprNamed { arg, .. }
        | FunctionArg::Unnamed(arg) => {
            if let FunctionArgExpr::Expr(expr) = arg {
                fix_expr(expr, rule_filter);
            }
        }
    }
}

fn is_count_rowcount_numeric_literal(func: &Function) -> bool {
    if !func.name.to_string().eq_ignore_ascii_case("COUNT") {
        return false;
    }

    let FunctionArguments::List(arg_list) = &func.args else {
        return false;
    };

    if arg_list.duplicate_treatment.is_some() || !arg_list.clauses.is_empty() {
        return false;
    }

    if arg_list.args.len() != 1 {
        return false;
    }

    matches!(
        &arg_list.args[0],
        FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(ValueWithSpan {
            value: Value::Number(n, _),
            ..
        }))) if numeric_literal_matches(n, 1) || numeric_literal_matches(n, 0)
    )
}

fn numeric_literal_matches(raw: &str, expected: u8) -> bool {
    raw.trim()
        .parse::<u64>()
        .ok()
        .is_some_and(|value| value == expected as u64)
}

fn null_comparison_rewrite(expr: &Expr) -> Option<Expr> {
    let Expr::BinaryOp { left, op, right } = expr else {
        return None;
    };

    let target = if lint_helpers::is_null_expr(right) {
        left.as_ref().clone()
    } else if lint_helpers::is_null_expr(left) {
        right.as_ref().clone()
    } else {
        return None;
    };

    match op {
        BinaryOperator::Eq => Some(Expr::IsNull(Box::new(target))),
        BinaryOperator::NotEq => Some(Expr::IsNotNull(Box::new(target))),
        _ => None,
    }
}

fn simple_case_rewrite(expr: &Expr) -> Option<Expr> {
    let Expr::Case {
        case_token,
        operand: None,
        conditions,
        else_result,
        end_token,
    } = expr
    else {
        return None;
    };

    if conditions.len() < 2 {
        return None;
    }

    let mut common_operand: Option<Expr> = None;
    let mut rewritten_conditions = Vec::with_capacity(conditions.len());

    for case_when in conditions {
        let (operand_expr, value_expr) =
            split_case_when_equality(&case_when.condition, common_operand.as_ref())?;

        if common_operand.is_none() {
            common_operand = Some(operand_expr);
        }

        rewritten_conditions.push(CaseWhen {
            condition: value_expr,
            result: case_when.result.clone(),
        });
    }

    Some(Expr::Case {
        case_token: case_token.clone(),
        operand: Some(Box::new(common_operand?)),
        conditions: rewritten_conditions,
        else_result: else_result.clone(),
        end_token: end_token.clone(),
    })
}

fn split_case_when_equality(
    condition: &Expr,
    expected_operand: Option<&Expr>,
) -> Option<(Expr, Expr)> {
    let Expr::BinaryOp { left, op, right } = condition else {
        return None;
    };

    if *op != BinaryOperator::Eq {
        return None;
    }

    if let Some(expected) = expected_operand {
        if exprs_equivalent(left, expected) {
            return Some((left.as_ref().clone(), right.as_ref().clone()));
        }
        if exprs_equivalent(right, expected) {
            return Some((right.as_ref().clone(), left.as_ref().clone()));
        }
        return None;
    }

    if simple_case_operand_candidate(left) {
        return Some((left.as_ref().clone(), right.as_ref().clone()));
    }
    if simple_case_operand_candidate(right) {
        return Some((right.as_ref().clone(), left.as_ref().clone()));
    }

    None
}

fn simple_case_operand_candidate(expr: &Expr) -> bool {
    matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))
}

fn exprs_equivalent(left: &Expr, right: &Expr) -> bool {
    format!("{left}") == format!("{right}")
}

fn nested_case_rewrite(expr: &Expr) -> Option<Expr> {
    let Expr::Case {
        case_token,
        operand: outer_operand,
        conditions: outer_conditions,
        else_result: Some(outer_else),
        end_token,
    } = expr
    else {
        return None;
    };

    if outer_conditions.is_empty() {
        return None;
    }

    let Expr::Case {
        operand: inner_operand,
        conditions: inner_conditions,
        else_result: inner_else,
        ..
    } = nested_case_expr(outer_else.as_ref())?
    else {
        return None;
    };

    if inner_conditions.is_empty() {
        return None;
    }

    if !case_operands_match(outer_operand.as_deref(), inner_operand.as_deref()) {
        return None;
    }

    let mut merged_conditions = outer_conditions.clone();
    merged_conditions.extend(inner_conditions.iter().cloned());

    Some(Expr::Case {
        case_token: case_token.clone(),
        operand: outer_operand.clone(),
        conditions: merged_conditions,
        else_result: inner_else.clone(),
        end_token: end_token.clone(),
    })
}

fn nested_case_expr(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::Case { .. } => Some(expr),
        Expr::Nested(inner) => nested_case_expr(inner),
        _ => None,
    }
}

fn case_operands_match(outer: Option<&Expr>, inner: Option<&Expr>) -> bool {
    match (outer, inner) {
        (None, None) => true,
        (Some(left), Some(right)) => format!("{left}") == format!("{right}"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowscope_core::{analyze, issue_codes, AnalysisOptions, AnalyzeRequest, LintConfig};

    fn default_lint_config() -> LintConfig {
        LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::new(),
        }
    }

    fn lint_rule_count_with_config(sql: &str, code: &str, lint_config: &LintConfig) -> usize {
        let request = AnalyzeRequest {
            sql: sql.to_string(),
            files: None,
            dialect: Dialect::Generic,
            source_name: None,
            options: Some(AnalysisOptions {
                lint: Some(lint_config.clone()),
                ..Default::default()
            }),
            schema: None,
            #[cfg(feature = "templating")]
            template_config: None,
        };

        analyze(&request)
            .issues
            .iter()
            .filter(|issue| issue.code == code)
            .count()
    }

    fn lint_rule_count(sql: &str, code: &str) -> usize {
        lint_rule_count_with_config(sql, code, &default_lint_config())
    }

    fn apply_fix_with_config(sql: &str, lint_config: &LintConfig) -> FixOutcome {
        apply_lint_fixes_with_lint_config(sql, Dialect::Generic, lint_config).expect("fix result")
    }

    #[test]
    fn am005_mode_reads_from_lint_config() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "ambiguous.join".to_string(),
                serde_json::json!({"fully_qualify_join_types": "outer"}),
            )]),
        };
        let filter = RuleFilter::from_lint_config(&lint_config);
        assert_eq!(filter.am005_mode, Am005QualifyMode::Outer);
    }

    #[test]
    fn am005_outer_mode_full_join_fix_output() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_CV_008.to_string()],
            rule_configs: std::collections::BTreeMap::from([(
                "ambiguous.join".to_string(),
                serde_json::json!({"fully_qualify_join_types": "outer"}),
            )]),
        };
        let sql = "SELECT a FROM t FULL JOIN u ON t.id = u.id";
        assert_eq!(
            lint_rule_count_with_config(
                "SELECT a FROM t FULL OUTER JOIN u ON t.id = u.id",
                issue_codes::LINT_AM_005,
                &lint_config,
            ),
            0
        );
        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.to_ascii_uppercase().contains("FULL OUTER JOIN"),
            "expected FULL OUTER JOIN in fixed SQL, got: {}",
            out.sql
        );
        assert_eq!(fix_count_for_code(&out.counts, issue_codes::LINT_AM_005), 1);
    }

    #[test]
    fn replace_full_join_outside_single_quotes_rewrites_keyword() {
        let sql = "SELECT a FROM t FULL JOIN u ON t.id = u.id";
        let rewritten = replace_full_join_outside_single_quotes(sql);
        assert_eq!(
            rewritten,
            "SELECT a FROM t full outer join u ON t.id = u.id"
        );
    }

    fn fix_count_for_code(counts: &FixCounts, code: &str) -> usize {
        counts.get(code)
    }

    #[test]
    fn lint_rule_counts_includes_parse_errors() {
        let counts = lint_rule_counts("SELECT (", Dialect::Generic, &default_lint_config());
        assert!(
            counts.get(issue_codes::PARSE_ERROR).copied().unwrap_or(0) > 0,
            "invalid SQL should contribute PARSE_ERROR to regression counts"
        );
    }

    #[test]
    fn parse_error_regression_is_detected_even_with_lint_improvements() {
        let before = std::collections::BTreeMap::from([(issue_codes::LINT_ST_005.to_string(), 1)]);
        let after = std::collections::BTreeMap::from([(issue_codes::PARSE_ERROR.to_string(), 1)]);
        let removed = FixCounts::from_removed(&before, &after);

        assert_eq!(
            removed.total(),
            1,
            "lint-only comparison can still look improved"
        );
        assert!(
            parse_errors_increased(&before, &after),
            "introduced parse errors must force regression"
        );
    }

    fn assert_rule_case(
        sql: &str,
        code: &str,
        expected_before: usize,
        expected_after: usize,
        expected_fix_count: usize,
    ) {
        let before = lint_rule_count(sql, code);
        assert_eq!(
            before, expected_before,
            "unexpected initial lint count for {code} in SQL: {sql}"
        );

        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            !out.skipped_due_to_comments,
            "test SQL should not be skipped"
        );
        assert_eq!(
            fix_count_for_code(&out.counts, code),
            expected_fix_count,
            "unexpected fix count for {code} in SQL: {sql}"
        );

        if expected_fix_count > 0 {
            assert!(out.changed, "expected SQL to change for {code}: {sql}");
        }

        let after = lint_rule_count(&out.sql, code);
        assert_eq!(
            after, expected_after,
            "unexpected lint count after fix for {code}. SQL: {}",
            out.sql
        );

        let second_pass = apply_lint_fixes(&out.sql, Dialect::Generic, &[]).unwrap_or_else(|err| {
            panic!("second pass failed for SQL:\n{}\nerror: {err:?}", out.sql);
        });
        assert_eq!(
            fix_count_for_code(&second_pass.counts, code),
            0,
            "expected idempotent second pass for {code}"
        );
    }

    fn assert_rule_case_with_config(
        sql: &str,
        code: &str,
        expected_before: usize,
        expected_after: usize,
        expected_fix_count: usize,
        lint_config: &LintConfig,
    ) {
        let before = lint_rule_count_with_config(sql, code, lint_config);
        assert_eq!(
            before, expected_before,
            "unexpected initial lint count for {code} in SQL: {sql}"
        );

        let out = apply_fix_with_config(sql, lint_config);
        assert!(
            !out.skipped_due_to_comments,
            "test SQL should not be skipped"
        );
        assert_eq!(
            fix_count_for_code(&out.counts, code),
            expected_fix_count,
            "unexpected fix count for {code} in SQL: {sql}"
        );

        if expected_fix_count > 0 {
            assert!(out.changed, "expected SQL to change for {code}: {sql}");
        }

        let after = lint_rule_count_with_config(&out.sql, code, lint_config);
        assert_eq!(
            after, expected_after,
            "unexpected lint count after fix for {code}. SQL: {}",
            out.sql
        );

        let second_pass = apply_fix_with_config(&out.sql, lint_config);
        assert_eq!(
            fix_count_for_code(&second_pass.counts, code),
            0,
            "expected idempotent second pass for {code}"
        );
    }

    #[test]
    fn sqlfluff_am003_cases_are_fixed() {
        let cases = [
            ("SELECT DISTINCT col FROM t GROUP BY col", 1, 0, 1),
            (
                "SELECT * FROM (SELECT DISTINCT a FROM t GROUP BY a) AS sub",
                1,
                0,
                1,
            ),
            (
                "WITH cte AS (SELECT DISTINCT a FROM t GROUP BY a) SELECT * FROM cte",
                1,
                0,
                1,
            ),
            (
                "CREATE VIEW v AS SELECT DISTINCT a FROM t GROUP BY a",
                1,
                0,
                1,
            ),
            (
                "INSERT INTO target SELECT DISTINCT a FROM t GROUP BY a",
                1,
                0,
                1,
            ),
            (
                "SELECT a FROM t UNION ALL SELECT DISTINCT b FROM t2 GROUP BY b",
                1,
                0,
                1,
            ),
            ("SELECT a, b FROM t", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_AM_001, before, after, fix_count);
        }
    }

    #[test]
    fn sqlfluff_am001_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT a, b FROM tbl UNION SELECT c, d FROM tbl1",
                1,
                0,
                1,
                Some("DISTINCT SELECT"),
            ),
            (
                "SELECT a, b FROM tbl UNION ALL SELECT c, d FROM tbl1",
                0,
                0,
                0,
                None,
            ),
            (
                "SELECT a, b FROM tbl UNION DISTINCT SELECT c, d FROM tbl1",
                0,
                0,
                0,
                None,
            ),
            (
                "select a, b from tbl union select c, d from tbl1",
                1,
                0,
                1,
                Some("DISTINCT SELECT"),
            ),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_AM_002, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_am005_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT * FROM t ORDER BY a, b DESC",
                1,
                0,
                1,
                Some("ORDER BY A ASC, B DESC"),
            ),
            (
                "SELECT * FROM t ORDER BY a DESC, b",
                1,
                0,
                1,
                Some("ORDER BY A DESC, B ASC"),
            ),
            (
                "SELECT * FROM t ORDER BY a DESC, b NULLS LAST",
                1,
                0,
                1,
                Some("ORDER BY A DESC, B ASC NULLS LAST"),
            ),
            ("SELECT * FROM t ORDER BY a, b", 0, 0, 0, None),
            ("SELECT * FROM t ORDER BY a ASC, b DESC", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_AM_003, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_am006_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT a FROM t JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("INNER JOIN"),
            ),
            (
                "SELECT a FROM t JOIN u ON t.id = u.id JOIN v ON u.id = v.id",
                2,
                0,
                2,
                Some("INNER JOIN U"),
            ),
            ("SELECT a FROM t INNER JOIN u ON t.id = u.id", 0, 0, 0, None),
            ("SELECT a FROM t LEFT JOIN u ON t.id = u.id", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_AM_005, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_am005_outer_and_both_configs_are_fixed() {
        let outer_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_CV_008.to_string()],
            rule_configs: std::collections::BTreeMap::from([(
                "ambiguous.join".to_string(),
                serde_json::json!({"fully_qualify_join_types": "outer"}),
            )]),
        };
        let both_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_CV_008.to_string()],
            rule_configs: std::collections::BTreeMap::from([(
                "ambiguous.join".to_string(),
                serde_json::json!({"fully_qualify_join_types": "both"}),
            )]),
        };

        let outer_cases = [
            (
                "SELECT a FROM t LEFT JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("LEFT OUTER JOIN"),
            ),
            (
                "SELECT a FROM t RIGHT JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("RIGHT OUTER JOIN"),
            ),
            (
                "SELECT a FROM t FULL JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("FULL OUTER JOIN"),
            ),
            (
                "SELECT a FROM t full join u ON t.id = u.id",
                1,
                0,
                1,
                Some("FULL OUTER JOIN"),
            ),
            ("SELECT a FROM t JOIN u ON t.id = u.id", 0, 0, 0, None),
        ];
        for (sql, before, after, fix_count, expected_text) in outer_cases {
            assert_rule_case_with_config(
                sql,
                issue_codes::LINT_AM_005,
                before,
                after,
                fix_count,
                &outer_config,
            );
            if let Some(expected) = expected_text {
                let out = apply_fix_with_config(sql, &outer_config);
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }

        let both_cases = [
            (
                "SELECT a FROM t JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("INNER JOIN"),
            ),
            (
                "SELECT a FROM t LEFT JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("LEFT OUTER JOIN"),
            ),
            (
                "SELECT a FROM t FULL JOIN u ON t.id = u.id",
                1,
                0,
                1,
                Some("FULL OUTER JOIN"),
            ),
        ];
        for (sql, before, after, fix_count, expected_text) in both_cases {
            assert_rule_case_with_config(
                sql,
                issue_codes::LINT_AM_005,
                before,
                after,
                fix_count,
                &both_config,
            );
            if let Some(expected) = expected_text {
                let out = apply_fix_with_config(sql, &both_config);
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_am009_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT foo.a, bar.b FROM foo INNER JOIN bar",
                1,
                0,
                1,
                Some("CROSS JOIN BAR"),
            ),
            (
                "SELECT foo.a, bar.b FROM foo LEFT JOIN bar",
                1,
                0,
                1,
                Some("CROSS JOIN BAR"),
            ),
            (
                "SELECT foo.a, bar.b FROM foo JOIN bar WHERE foo.a = bar.a OR foo.x = 3",
                0,
                0,
                0,
                None,
            ),
            ("SELECT foo.a, bar.b FROM foo CROSS JOIN bar", 0, 0, 0, None),
            (
                "SELECT foo.id, bar.id FROM foo LEFT JOIN bar USING (id)",
                0,
                0,
                0,
                None,
            ),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_AM_008, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_al007_force_enabled_single_table_alias_is_fixed() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.forbid".to_string(),
                serde_json::json!({"force_enable": true}),
            )]),
        };
        let sql = "SELECT u.id FROM users u";
        assert_rule_case_with_config(sql, issue_codes::LINT_AL_007, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        let fixed_upper = out.sql.to_ascii_uppercase();
        assert!(
            fixed_upper.contains("FROM USERS"),
            "expected table alias to be removed: {}",
            out.sql
        );
        assert!(
            !fixed_upper.contains("FROM USERS U"),
            "expected unnecessary table alias to be removed: {}",
            out.sql
        );
        assert!(
            fixed_upper.contains("USERS.ID"),
            "expected references to use table name after alias removal: {}",
            out.sql
        );
    }

    #[test]
    fn sqlfluff_al009_fix_respects_case_sensitive_mode() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "aliasing.self_alias.column".to_string(),
                serde_json::json!({"alias_case_check": "case_sensitive"}),
            )]),
        };
        let sql = "SELECT a AS A FROM t";
        assert_rule_case_with_config(sql, issue_codes::LINT_AL_009, 0, 0, 0, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.contains("AS A"),
            "case-sensitive mode should keep case-mismatched alias: {}",
            out.sql
        );
    }

    #[test]
    fn sqlfluff_al009_ast_fix_keeps_table_aliases() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_AL_007.to_string()],
            rule_configs: std::collections::BTreeMap::new(),
        };
        let sql = "SELECT t.a AS a FROM t AS t";
        assert_rule_case_with_config(sql, issue_codes::LINT_AL_009, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        let fixed_upper = out.sql.to_ascii_uppercase();
        assert!(
            fixed_upper.contains("FROM T AS T"),
            "AL09 fix should not remove table alias declarations: {}",
            out.sql
        );
        assert!(
            !fixed_upper.contains("T.A AS A"),
            "expected only column self-alias to be removed: {}",
            out.sql
        );
    }

    #[test]
    fn sqlfluff_st005_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' END FROM t",
                1,
                0,
                1,
                Some("CASE X WHEN 1 THEN 'A' WHEN 2 THEN 'B' END"),
            ),
            (
                "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' ELSE 'c' END FROM t",
                1,
                0,
                1,
                Some("CASE X WHEN 1 THEN 'A' WHEN 2 THEN 'B' ELSE 'C' END"),
            ),
            (
                "SELECT CASE WHEN x = 1 THEN 'a' WHEN y = 2 THEN 'b' END FROM t",
                0,
                0,
                0,
                None,
            ),
            (
                "SELECT CASE x WHEN 1 THEN 'a' WHEN 2 THEN 'b' END FROM t",
                0,
                0,
                0,
                None,
            ),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_002, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_st006_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT a + 1, a FROM t", 1, 0, 1, Some("SELECT A, A + 1")),
            (
                "SELECT a + 1, b + 2, a FROM t",
                1,
                0,
                1,
                Some("SELECT A, A + 1, B + 2"),
            ),
            (
                "SELECT a + 1, b AS b_alias FROM t",
                1,
                0,
                1,
                Some("SELECT B AS B_ALIAS, A + 1"),
            ),
            ("SELECT a, b + 1 FROM t", 0, 0, 0, None),
            ("SELECT a + 1, b + 2 FROM t", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_006, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_st008_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT DISTINCT(a) FROM t",
                1,
                0,
                1,
                Some("SELECT DISTINCT A"),
            ),
            ("SELECT DISTINCT a FROM t", 0, 0, 0, None),
            ("SELECT a FROM t", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_008, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_st009_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT foo.a, bar.b FROM foo LEFT JOIN bar ON bar.a = foo.a",
                1,
                0,
                1,
                Some("ON FOO.A = BAR.A"),
            ),
            (
                "SELECT foo.a, foo.b, bar.c FROM foo LEFT JOIN bar ON bar.a = foo.a AND bar.b = foo.b",
                1,
                0,
                1,
                Some("ON FOO.A = BAR.A AND FOO.B = BAR.B"),
            ),
            (
                "SELECT foo.a, bar.b FROM foo LEFT JOIN bar ON foo.a = bar.a",
                0,
                0,
                0,
                None,
            ),
            (
                "SELECT foo.a, bar.b FROM foo LEFT JOIN bar ON bar.b = a",
                0,
                0,
                0,
                None,
            ),
            (
                "SELECT foo.a, bar.b FROM foo AS x LEFT JOIN bar AS y ON y.a = x.a",
                1,
                0,
                1,
                Some("ON X.A = Y.A"),
            ),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_009, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_st007_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT * FROM a JOIN b USING (id)",
                1,
                0,
                1,
                Some("ON A.ID = B.ID"),
            ),
            (
                "SELECT * FROM a AS x JOIN b AS y USING (id)",
                1,
                0,
                1,
                Some("ON X.ID = Y.ID"),
            ),
            (
                "SELECT * FROM a JOIN b USING (id, tenant_id)",
                1,
                0,
                1,
                Some("ON A.ID = B.ID AND A.TENANT_ID = B.TENANT_ID"),
            ),
            ("SELECT * FROM a JOIN b ON a.id = b.id", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_007, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_st004_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT CASE WHEN species = 'Rat' THEN 'Squeak' ELSE CASE WHEN species = 'Dog' THEN 'Woof' END END AS sound FROM mytable",
                1,
                0,
                1,
                Some("WHEN 'DOG' THEN 'WOOF'"),
            ),
            (
                "SELECT CASE WHEN species = 'Rat' THEN 'Squeak' ELSE CASE WHEN species = 'Dog' THEN 'Woof' WHEN species = 'Mouse' THEN 'Squeak' ELSE 'Other' END END AS sound FROM mytable",
                1,
                0,
                1,
                Some("WHEN 'MOUSE' THEN 'SQUEAK' ELSE 'OTHER' END"),
            ),
            (
                "SELECT CASE WHEN species = 'Rat' THEN CASE WHEN colour = 'Black' THEN 'Growl' WHEN colour = 'Grey' THEN 'Squeak' END END AS sound FROM mytable",
                0,
                0,
                0,
                None,
            ),
            (
                "SELECT CASE WHEN day_of_month IN (11, 12, 13) THEN 'TH' ELSE CASE MOD(day_of_month, 10) WHEN 1 THEN 'ST' WHEN 2 THEN 'ND' WHEN 3 THEN 'RD' ELSE 'TH' END END AS ordinal_suffix FROM calendar",
                0,
                0,
                0,
                None,
            ),
            (
                "SELECT CASE x WHEN 0 THEN 'zero' WHEN 5 THEN 'five' ELSE CASE x WHEN 10 THEN 'ten' WHEN 20 THEN 'twenty' ELSE 'other' END END FROM tab_a",
                1,
                0,
                1,
                Some("WHEN 20 THEN 'TWENTY' ELSE 'OTHER' END"),
            ),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_004, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_cv003_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT a FROM foo WHERE a IS NULL", 0, 0, 0, None),
            ("SELECT a FROM foo WHERE a IS NOT NULL", 0, 0, 0, None),
            (
                "SELECT a FROM foo WHERE a <> NULL",
                1,
                0,
                1,
                Some("WHERE A IS NOT NULL"),
            ),
            (
                "SELECT a FROM foo WHERE a <> NULL AND b != NULL AND c = 'foo'",
                2,
                0,
                2,
                Some("A IS NOT NULL AND B IS NOT NULL"),
            ),
            (
                "SELECT a FROM foo WHERE a = NULL",
                1,
                0,
                1,
                Some("WHERE A IS NULL"),
            ),
            (
                "SELECT a FROM foo WHERE a=NULL",
                1,
                0,
                1,
                Some("WHERE A IS NULL"),
            ),
            (
                "SELECT a FROM foo WHERE a = b OR (c > d OR e = NULL)",
                1,
                0,
                1,
                Some("OR E IS NULL"),
            ),
            ("UPDATE table1 SET col = NULL WHERE col = ''", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_005, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_cv001_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT coalesce(foo, 0) AS bar FROM baz", 0, 0, 0),
            ("SELECT ifnull(foo, 0) AS bar FROM baz", 1, 0, 1),
            ("SELECT nvl(foo, 0) AS bar FROM baz", 1, 0, 1),
            (
                "SELECT CASE WHEN x IS NULL THEN 'default' ELSE x END FROM t",
                0,
                0,
                0,
            ),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_002, before, after, fix_count);
        }
    }

    #[test]
    fn sqlfluff_cv003_trailing_comma_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT a, FROM t", 1, 0, 1),
            ("SELECT a , FROM t", 1, 0, 1),
            ("SELECT a FROM t", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_003, before, after, fix_count);
        }
    }

    #[test]
    fn sqlfluff_cv001_not_equal_style_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT * FROM t WHERE a <> b AND c != d", 1, 0, 1),
            ("SELECT * FROM t WHERE a != b", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_001, before, after, fix_count);
        }
    }

    #[test]
    fn sqlfluff_cv008_cases_are_fixed_or_unchanged() {
        let cases = [
            (
                "SELECT * FROM a RIGHT JOIN b ON a.id = b.id",
                1,
                0,
                1,
                Some("FROM B LEFT JOIN"),
            ),
            (
                "SELECT a.id FROM a JOIN b ON a.id = b.id RIGHT JOIN c ON b.id = c.id",
                1,
                0,
                1,
                Some("FROM C LEFT JOIN"),
            ),
            (
                "SELECT a.id FROM a RIGHT JOIN b ON a.id = b.id RIGHT JOIN c ON b.id = c.id",
                2,
                0,
                2,
                Some("FROM C LEFT JOIN"),
            ),
            ("SELECT * FROM a LEFT JOIN b ON a.id = b.id", 0, 0, 0, None),
        ];

        for (sql, before, after, fix_count, expected_text) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_008, before, after, fix_count);

            if let Some(expected) = expected_text {
                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert!(
                    out.sql.to_ascii_uppercase().contains(expected),
                    "expected {expected:?} in fixed SQL, got: {}",
                    out.sql
                );
            }
        }
    }

    #[test]
    fn sqlfluff_cv007_cases_are_fixed_or_unchanged() {
        let cases = [
            ("(SELECT 1)", 1, 0, 1),
            ("((SELECT 1))", 1, 0, 1),
            ("SELECT 1", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_007, before, after, fix_count);
        }
    }

    #[test]
    fn cv007_fix_respects_disabled_rules() {
        let sql = "(SELECT 1)";
        let out = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_CV_007.to_string()],
        )
        .expect("fix result");
        assert_eq!(out.sql, sql);
        assert_eq!(out.counts.get(issue_codes::LINT_CV_007), 0);
    }

    #[test]
    fn cv010_fix_respects_single_quote_preference_without_rf006() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_RF_006.to_string()],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.quoted_literals".to_string(),
                serde_json::json!({"preferred_quoted_literal_style": "single_quotes"}),
            )]),
        };
        let sql = "SELECT 'abc' AS a, \"good_name\" AS b FROM t";
        assert_rule_case_with_config(sql, issue_codes::LINT_CV_010, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.contains("good_name"),
            "expected safe identifier unquoting for CV_010 fix: {}",
            out.sql
        );
        assert!(
            !out.sql.contains("\"good_name\""),
            "expected double-quoted identifier to be rewritten: {}",
            out.sql
        );
    }

    #[test]
    fn cv011_cast_preference_rewrites_double_colon_style() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.casting_style".to_string(),
                serde_json::json!({"preferred_type_casting_style": "cast"}),
            )]),
        };
        let sql = "SELECT amount::INT FROM t";
        assert_rule_case_with_config(sql, issue_codes::LINT_CV_011, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.to_ascii_uppercase().contains("CAST(AMOUNT AS INT)"),
            "expected CAST(...) rewrite for CV_011 fix: {}",
            out.sql
        );
    }

    #[test]
    fn cv011_shorthand_preference_rewrites_cast_style_when_safe() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_CV_011".to_string(),
                serde_json::json!({"preferred_type_casting_style": "shorthand"}),
            )]),
        };
        let sql = "SELECT CAST(amount AS INT) FROM t";
        assert_rule_case_with_config(sql, issue_codes::LINT_CV_011, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.to_ascii_uppercase().contains("AMOUNT::INT"),
            "expected :: rewrite for CV_011 fix: {}",
            out.sql
        );
    }

    #[test]
    fn sqlfluff_st012_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT 1;;", 1, 0, 1),
            ("SELECT 1;\n \t ;", 1, 0, 1),
            ("SELECT 1;", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_012, before, after, fix_count);
        }
    }

    #[test]
    fn sqlfluff_st002_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT CASE WHEN x > 1 THEN 'a' ELSE NULL END FROM t", 1, 0, 1),
            (
                "SELECT CASE name WHEN 'cat' THEN 'meow' WHEN 'dog' THEN 'woof' ELSE NULL END FROM t",
                1,
                0,
                1,
            ),
            (
                "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' WHEN x = 3 THEN 'c' ELSE NULL END FROM t",
                1,
                0,
                1,
            ),
            (
                "SELECT CASE WHEN x > 0 THEN CASE WHEN y > 0 THEN 'pos' ELSE NULL END ELSE NULL END FROM t",
                2,
                0,
                2,
            ),
            (
                "SELECT * FROM t WHERE (CASE WHEN x > 0 THEN 1 ELSE NULL END) IS NOT NULL",
                1,
                0,
                1,
            ),
            (
                "WITH cte AS (SELECT CASE WHEN x > 0 THEN 'yes' ELSE NULL END AS flag FROM t) SELECT * FROM cte",
                1,
                0,
                1,
            ),
            ("SELECT CASE WHEN x > 1 THEN 'a' END FROM t", 0, 0, 0),
            (
                "SELECT CASE name WHEN 'cat' THEN 'meow' ELSE UPPER(name) END FROM t",
                0,
                0,
                0,
            ),
            ("SELECT CASE WHEN x > 1 THEN 'a' ELSE 'b' END FROM t", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_ST_001, before, after, fix_count);
        }
    }

    #[test]
    fn count_style_cases_are_fixed_or_unchanged() {
        let cases = [
            ("SELECT COUNT(1) FROM t", 1, 0, 1),
            (
                "SELECT col FROM t GROUP BY col HAVING COUNT(1) > 5",
                1,
                0,
                1,
            ),
            (
                "SELECT * FROM t WHERE id IN (SELECT COUNT(1) FROM t2 GROUP BY col)",
                1,
                0,
                1,
            ),
            ("SELECT COUNT(1), COUNT(1) FROM t", 2, 0, 2),
            (
                "WITH cte AS (SELECT COUNT(1) AS cnt FROM t) SELECT * FROM cte",
                1,
                0,
                1,
            ),
            ("SELECT COUNT(*) FROM t", 0, 0, 0),
            ("SELECT COUNT(id) FROM t", 0, 0, 0),
            ("SELECT COUNT(0) FROM t", 1, 0, 1),
            ("SELECT COUNT(01) FROM t", 1, 0, 1),
            ("SELECT COUNT(DISTINCT id) FROM t", 0, 0, 0),
        ];

        for (sql, before, after, fix_count) in cases {
            assert_rule_case(sql, issue_codes::LINT_CV_004, before, after, fix_count);
        }
    }

    #[test]
    fn skips_files_with_comments() {
        let sql = "-- keep this comment\nSELECT COUNT(1) FROM t";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(!out.changed);
        assert!(out.skipped_due_to_comments);
        assert_eq!(out.sql, sql);
    }

    #[test]
    fn skips_files_with_mysql_hash_comments() {
        let sql = "# keep this comment\nSELECT COUNT(1) FROM t";
        let out = apply_lint_fixes(sql, Dialect::Mysql, &[]).expect("fix result");
        assert!(!out.changed);
        assert!(out.skipped_due_to_comments);
        assert_eq!(out.sql, sql);
    }
    #[test]
    fn does_not_treat_double_quoted_comment_markers_as_comments() {
        let sql = "SELECT \"a--b\", \"x/*y\" FROM t";
        assert!(!contains_comment_markers(sql, Dialect::Generic));
    }

    #[test]
    fn does_not_treat_backtick_or_bracketed_markers_as_comments() {
        let sql = "SELECT `a--b`, [x/*y] FROM t";
        assert!(!contains_comment_markers(sql, Dialect::Mysql));
    }

    #[test]
    fn fix_mode_does_not_skip_double_quoted_markers() {
        let sql = "SELECT \"a--b\", COUNT(1) FROM t";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(!out.skipped_due_to_comments);
    }

    #[test]
    fn fix_mode_does_not_skip_backtick_markers() {
        let sql = "SELECT `a--b`, COUNT(1) FROM t";
        let out = apply_lint_fixes(sql, Dialect::Mysql, &[]).expect("fix result");
        assert!(!out.skipped_due_to_comments);
    }

    #[test]
    fn does_not_collapse_independent_select_statements() {
        let sql = "SELECT 1; SELECT 2;";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            !out.sql.to_ascii_uppercase().contains("DISTINCT SELECT"),
            "auto-fix must preserve statement boundaries: {}",
            out.sql
        );
        let parsed = parse_sql_with_dialect(&out.sql, Dialect::Generic).expect("parse fixed sql");
        assert_eq!(
            parsed.len(),
            2,
            "auto-fix should preserve two independent statements"
        );
    }

    #[test]
    fn subquery_to_cte_text_fix_applies() {
        let fixed = fix_subquery_to_cte("SELECT * FROM (SELECT 1) sub");
        assert_eq!(fixed, "WITH sub AS (SELECT 1) SELECT * FROM sub");
    }

    #[test]
    fn text_fix_pipeline_converts_subquery_to_cte() {
        let fixed = apply_text_fixes(
            "SELECT * FROM (SELECT 1) sub",
            &RuleFilter::default(),
            Dialect::Generic,
        );
        assert!(
            fixed.to_ascii_uppercase().contains("WITH SUB AS"),
            "expected CTE rewrite, got: {fixed}"
        );
    }

    #[test]
    fn subquery_to_cte_text_fix_handles_nested_parentheses() {
        let fixed = fix_subquery_to_cte("SELECT * FROM (SELECT COUNT(*) FROM t) sub");
        assert_eq!(
            fixed,
            "WITH sub AS (SELECT COUNT(*) FROM t) SELECT * FROM sub"
        );
        parse_sql_with_dialect(&fixed, Dialect::Generic).expect("fixed SQL should parse");
    }

    #[test]
    fn st005_ast_fix_rewrites_simple_join_derived_subquery_to_cte() {
        let sql = "SELECT t.id FROM t JOIN (SELECT id FROM u) sub ON t.id = sub.id";
        assert_rule_case(sql, issue_codes::LINT_ST_005, 1, 0, 1);

        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            out.sql.to_ascii_uppercase().contains("WITH SUB AS"),
            "expected AST ST_005 rewrite to emit CTE: {}",
            out.sql
        );
    }

    #[test]
    fn st005_ast_fix_rewrites_simple_from_derived_subquery_with_config() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "structure.subquery".to_string(),
                serde_json::json!({"forbid_subquery_in": "from"}),
            )]),
        };
        let sql = "SELECT sub.id FROM (SELECT id FROM u) sub";
        assert_rule_case_with_config(sql, issue_codes::LINT_ST_005, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.to_ascii_uppercase().contains("WITH SUB AS"),
            "expected FROM-derived ST_005 rewrite to emit CTE: {}",
            out.sql
        );
    }

    #[test]
    fn consecutive_semicolon_fix_ignores_string_literal_content() {
        let sql = "SELECT 'a;;b' AS txt;;";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            out.sql.contains("'a;;b'"),
            "string literal content must be preserved: {}",
            out.sql
        );
        assert!(
            out.sql.trim_end().ends_with(';') && !out.sql.trim_end().ends_with(";;"),
            "trailing semicolon run should be collapsed to one terminator: {}",
            out.sql
        );
    }

    #[test]
    fn consecutive_semicolon_fix_collapses_whitespace_separated_runs() {
        let fixed = fix_consecutive_semicolons("SELECT 1;\n \t ;", Dialect::Generic);
        assert_eq!(fixed, "SELECT 1;");
    }

    #[test]
    fn lint_fix_subquery_with_function_call_is_parseable() {
        let sql = "SELECT * FROM (SELECT COUNT(*) FROM t) sub";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            !out.skipped_due_to_regression,
            "function-call subquery rewrite should not be treated as regression: {}",
            out.sql
        );
        parse_sql_with_dialect(&out.sql, Dialect::Generic).expect("fixed SQL should parse");
    }

    #[test]
    fn distinct_parentheses_fix_preserves_valid_sql() {
        let sql = "SELECT DISTINCT(a) FROM t";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            !out.sql.contains("a)"),
            "unexpected dangling parenthesis after fix: {}",
            out.sql
        );
        parse_sql_with_dialect(&out.sql, Dialect::Generic).expect("fixed SQL should parse");
    }

    #[test]
    fn not_equal_fix_does_not_rewrite_string_literals() {
        let sql = "SELECT '<>' AS x, a<>b, c!=d FROM t";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            out.sql.contains("'<>'"),
            "string literal should remain unchanged: {}",
            out.sql
        );
        assert!(
            out.sql.contains("a != b"),
            "operator usage should still be normalized: {}",
            out.sql
        );
    }

    #[test]
    fn case_style_fix_does_not_rewrite_double_quoted_identifiers() {
        let fixed = fix_case_style_consistency("SELECT \"FROM\", \"CamelCase\" FROM t");
        assert!(
            fixed.contains("\"FROM\""),
            "keyword-like quoted identifier should remain unchanged: {fixed}"
        );
        assert!(
            fixed.contains("\"CamelCase\""),
            "case-sensitive quoted identifier should remain unchanged: {fixed}"
        );
    }

    #[test]
    fn spacing_fixes_do_not_rewrite_single_quoted_literals() {
        let operator_fixed = fix_operator_spacing("SELECT a=1, 'x=y' FROM t", Dialect::Generic);
        assert!(
            operator_fixed.contains("'x=y'"),
            "operator spacing must not mutate literals: {operator_fixed}"
        );
        assert!(
            operator_fixed.contains("a = 1"),
            "operator spacing should still apply: {operator_fixed}"
        );

        let comma_fixed = fix_comma_spacing("SELECT a,b, 'x,y' FROM t", Dialect::Generic);
        assert!(
            comma_fixed.contains("'x,y'"),
            "comma spacing must not mutate literals: {comma_fixed}"
        );
        assert!(
            comma_fixed.contains("a, b"),
            "comma spacing should still apply: {comma_fixed}"
        );
    }

    #[test]
    fn keyword_newline_fix_does_not_rewrite_literals_or_quoted_identifiers() {
        let sql = "SELECT COUNT(1), 'hello FROM world', \"x WHERE y\" FROM t WHERE a = 1";
        let fixed = fix_keyword_newlines(sql, Dialect::Generic);
        assert!(
            fixed.contains("'hello FROM world'"),
            "single-quoted literal should remain unchanged: {fixed}"
        );
        assert!(
            fixed.contains("\"x WHERE y\""),
            "double-quoted identifier should remain unchanged: {fixed}"
        );
        assert!(
            !fixed.contains("hello\nFROM world"),
            "keyword newline fix must not inject newlines into literals: {fixed}"
        );
        assert!(
            fixed.contains("\nFROM t"),
            "FROM clause should still be normalized: {fixed}"
        );
        assert!(
            fixed.contains("\nWHERE a = 1"),
            "WHERE clause should still be normalized: {fixed}"
        );
    }

    #[test]
    fn cp04_fix_reduces_literal_capitalisation_violations() {
        assert_rule_case(
            "SELECT NULL, true, False FROM t",
            issue_codes::LINT_CP_004,
            1,
            0,
            1,
        );
    }

    #[test]
    fn cp05_fix_reduces_type_capitalisation_violations() {
        assert_rule_case(
            "CREATE TABLE t (a INT, b VarChar(10));",
            issue_codes::LINT_CP_005,
            1,
            0,
            1,
        );
    }

    #[test]
    fn cv06_fix_adds_missing_final_terminator() {
        assert_rule_case("SELECT 1 ;", issue_codes::LINT_CV_006, 1, 0, 1);
    }

    #[test]
    fn lt03_fix_moves_trailing_operator_to_leading_position() {
        assert_rule_case("SELECT a +\n b FROM t", issue_codes::LINT_LT_003, 1, 0, 1);
    }

    #[test]
    fn alias_keyword_fix_respects_rf_004_rule_filter() {
        let sql = "select a from users as select";

        let rf_disabled = RuleFilter::new(&[
            issue_codes::LINT_LT_014.to_string(),
            issue_codes::LINT_RF_004.to_string(),
        ]);
        let out_rf_disabled = apply_text_fixes(sql, &rf_disabled, Dialect::Generic);
        assert_eq!(
            out_rf_disabled, sql,
            "excluding RF_004 should block alias-keyword rewrite"
        );

        let al_disabled = RuleFilter::new(&[
            issue_codes::LINT_LT_014.to_string(),
            issue_codes::LINT_AL_005.to_string(),
        ]);
        let out_al_disabled = apply_text_fixes(sql, &al_disabled, Dialect::Generic);
        assert!(
            out_al_disabled.contains("alias_select"),
            "excluding AL_005 must not block RF_004 rewrite: {out_al_disabled}"
        );
    }

    #[test]
    fn al001_fix_still_improves_with_fix_mode() {
        let sql = "SELECT * FROM a x JOIN b y ON x.id = y.id";
        assert_rule_case(sql, issue_codes::LINT_AL_001, 2, 0, 2);

        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        let upper = out.sql.to_ascii_uppercase();
        assert!(
            upper.contains("FROM A AS X"),
            "expected explicit alias in fixed SQL, got: {}",
            out.sql
        );
        assert!(
            upper.contains("JOIN B AS Y"),
            "expected explicit alias in fixed SQL, got: {}",
            out.sql
        );
    }

    #[test]
    fn al001_fix_does_not_synthesize_missing_aliases() {
        let sql = "SELECT COUNT(1) FROM users";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");

        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "expected non-AL001 fix to apply: {}",
            out.sql
        );
        assert!(
            !out.sql.to_ascii_uppercase().contains(" AS T"),
            "AL001 fixer must not generate synthetic aliases: {}",
            out.sql
        );
    }

    #[test]
    fn al001_disabled_preserves_implicit_aliases_when_other_rules_fix() {
        let sql = "select count(1) from a x join b y on x.id = y.id";
        let out = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_AL_001.to_string()],
        )
        .expect("fix result");

        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "expected non-AL001 fix to apply: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("FROM A X"),
            "implicit alias should be preserved when AL001 is disabled: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("JOIN B Y"),
            "implicit alias should be preserved when AL001 is disabled: {}",
            out.sql
        );
        assert!(
            lint_rule_count(&out.sql, issue_codes::LINT_AL_001) > 0,
            "AL001 violations should remain when the rule is disabled: {}",
            out.sql
        );
    }

    #[test]
    fn al001_implicit_config_rewrites_explicit_aliases() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                issue_codes::LINT_AL_001.to_string(),
                serde_json::json!({"aliasing": "implicit"}),
            )]),
        };

        let sql = "SELECT COUNT(1) FROM a AS x JOIN b AS y ON x.id = y.id";
        assert_eq!(
            lint_rule_count_with_config(sql, issue_codes::LINT_AL_001, &lint_config),
            2,
            "explicit aliases should violate AL001 under implicit mode"
        );

        let out = apply_fix_with_config(sql, &lint_config);
        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "expected non-AL001 fix to apply: {}",
            out.sql
        );
        assert!(
            !out.sql.to_ascii_uppercase().contains(" AS X"),
            "implicit-mode AL001 should remove explicit aliases: {}",
            out.sql
        );
        assert!(
            !out.sql.to_ascii_uppercase().contains(" AS Y"),
            "implicit-mode AL001 should remove explicit aliases: {}",
            out.sql
        );
        assert_eq!(
            lint_rule_count_with_config(&out.sql, issue_codes::LINT_AL_001, &lint_config),
            0,
            "AL001 should be resolved under implicit mode: {}",
            out.sql
        );
    }

    #[test]
    fn excluded_rule_is_not_rewritten_when_other_rules_are_fixed() {
        let sql = "SELECT COUNT(1) FROM t WHERE a<>b";
        let disabled = vec![issue_codes::LINT_CV_001.to_string()];
        let out = apply_lint_fixes(sql, Dialect::Generic, &disabled).expect("fix result");
        assert!(
            out.sql.contains("COUNT(*)"),
            "expected COUNT style fix: {}",
            out.sql
        );
        assert!(
            out.sql.contains("<>"),
            "excluded CV_005 should remain '<>' (not '!='): {}",
            out.sql
        );
        assert!(
            !out.sql.contains("!="),
            "excluded CV_005 should not be rewritten to '!=': {}",
            out.sql
        );
    }

    #[test]
    fn references_quoting_fix_keeps_reserved_identifier_quotes() {
        let sql = "SELECT \"FROM\" FROM t UNION SELECT 2";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            out.sql.contains("\"FROM\""),
            "reserved identifier must remain quoted: {}",
            out.sql
        );
    }

    #[test]
    fn references_quoting_fix_keeps_case_sensitive_identifier_quotes() {
        let sql = "SELECT \"CamelCase\" FROM t UNION SELECT 2";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
        assert!(
            out.sql.contains("\"CamelCase\""),
            "case-sensitive identifier must remain quoted: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("DISTINCT SELECT"),
            "expected another fix to persist output: {}",
            out.sql
        );
    }

    #[test]
    fn sqlfluff_fix_rule_smoke_cases_reduce_target_violations() {
        let cases = vec![
            (
                issue_codes::LINT_AL_001,
                "SELECT * FROM a x JOIN b y ON x.id = y.id",
            ),
            (
                issue_codes::LINT_AL_005,
                "SELECT u.name FROM users u JOIN orders o ON users.id = orders.user_id",
            ),
            (issue_codes::LINT_AL_009, "SELECT a AS a FROM t"),
            (issue_codes::LINT_AM_002, "SELECT 1 UNION SELECT 2"),
            (
                issue_codes::LINT_AM_003,
                "SELECT * FROM t ORDER BY a, b DESC",
            ),
            (
                issue_codes::LINT_AM_005,
                "SELECT * FROM a JOIN b ON a.id = b.id",
            ),
            (
                issue_codes::LINT_AM_008,
                "SELECT foo.a, bar.b FROM foo INNER JOIN bar",
            ),
            (issue_codes::LINT_CP_001, "SELECT a from t"),
            (issue_codes::LINT_CP_004, "SELECT NULL, true FROM t"),
            (
                issue_codes::LINT_CP_005,
                "CREATE TABLE t (a INT, b varchar(10))",
            ),
            (
                issue_codes::LINT_CV_001,
                "SELECT * FROM t WHERE a <> b AND c != d",
            ),
            (
                issue_codes::LINT_CV_002,
                "SELECT IFNULL(x, 'default') FROM t",
            ),
            (issue_codes::LINT_CV_003, "SELECT a, FROM t"),
            (issue_codes::LINT_CV_004, "SELECT COUNT(1) FROM t"),
            (issue_codes::LINT_CV_005, "SELECT * FROM t WHERE a = NULL"),
            (issue_codes::LINT_CV_006, "SELECT 1 ;"),
            (issue_codes::LINT_CV_007, "(SELECT 1)"),
            (issue_codes::LINT_JJ_001, "SELECT '{{foo}}' AS templated"),
            (issue_codes::LINT_LT_001, "SELECT payload->>'id' FROM t"),
            (issue_codes::LINT_LT_002, "SELECT a\n   , b\nFROM t"),
            (issue_codes::LINT_LT_003, "SELECT a +\n b FROM t"),
            (issue_codes::LINT_LT_004, "SELECT a,b FROM t"),
            (issue_codes::LINT_LT_006, "SELECT COUNT (1) FROM t"),
            (
                issue_codes::LINT_LT_007,
                "WITH cte AS (\n  SELECT 1) SELECT * FROM cte",
            ),
            (issue_codes::LINT_LT_009, "SELECT a,b,c,d,e FROM t"),
            (issue_codes::LINT_LT_010, "SELECT\nDISTINCT a\nFROM t"),
            (
                issue_codes::LINT_LT_011,
                "SELECT 1 UNION SELECT 2\nUNION SELECT 3",
            ),
            (issue_codes::LINT_LT_012, "SELECT 1\nFROM t"),
            (issue_codes::LINT_LT_013, "\n\nSELECT 1"),
            (issue_codes::LINT_LT_014, "SELECT a FROM t\nWHERE a=1"),
            (issue_codes::LINT_LT_015, "SELECT 1\n\n\nFROM t"),
            (issue_codes::LINT_RF_003, "SELECT a.id, id2 FROM a"),
            (issue_codes::LINT_RF_006, "SELECT \"good_name\" FROM t"),
            (
                issue_codes::LINT_ST_001,
                "SELECT CASE WHEN x > 1 THEN 'a' ELSE NULL END FROM t",
            ),
            (
                issue_codes::LINT_ST_004,
                "SELECT CASE WHEN species = 'Rat' THEN 'Squeak' ELSE CASE WHEN species = 'Dog' THEN 'Woof' END END FROM mytable",
            ),
            (
                issue_codes::LINT_ST_002,
                "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' END FROM t",
            ),
            (
                issue_codes::LINT_ST_005,
                "SELECT * FROM t JOIN (SELECT * FROM u) sub ON t.id = sub.id",
            ),
            (issue_codes::LINT_ST_006, "SELECT a + 1, a FROM t"),
            (
                issue_codes::LINT_ST_007,
                "SELECT * FROM a JOIN b USING (id)",
            ),
            (issue_codes::LINT_ST_008, "SELECT DISTINCT(a) FROM t"),
            (
                issue_codes::LINT_ST_009,
                "SELECT * FROM a x JOIN b y ON y.id = x.id",
            ),
            (issue_codes::LINT_ST_012, "SELECT 1;;"),
        ];

        for (code, sql) in cases {
            let before = lint_rule_count(sql, code);
            assert!(before > 0, "expected {code} to trigger before fix: {sql}");
            let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
            assert!(
                !out.skipped_due_to_comments,
                "test SQL should not be skipped: {sql}"
            );
            let after = lint_rule_count(&out.sql, code);
            assert!(
                after < before || out.sql != sql,
                "expected {code} count to decrease or SQL to be rewritten. before={before} after={after}\ninput={sql}\noutput={}",
                out.sql
            );
        }
    }
}
