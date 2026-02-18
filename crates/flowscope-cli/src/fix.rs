//! SQL lint auto-fix helpers.
//!
//! Fixing is best-effort and deterministic. We combine:
//! - AST rewrites for structurally safe transforms.
//! - Text rewrites for parity-style formatting/convention rules.
//! - Lint before/after comparison to report per-rule removed violations.

use crate::fix_engine::{
    apply_edits as apply_patch_edits, derive_protected_ranges, plan_fixes, BlockedReason,
    Edit as PatchEdit, Fix as PatchFix, FixApplicability as PatchApplicability,
    ProtectedRange as PatchProtectedRange, ProtectedRangeKind as PatchProtectedRangeKind,
};
use flowscope_core::linter::config::canonicalize_rule_code;
use flowscope_core::{
    analyze, issue_codes, parse_sql_with_dialect, AnalysisOptions, AnalyzeRequest, Dialect, Issue,
    IssueAutofixApplicability, LintConfig, ParseError,
};
#[cfg(feature = "templating")]
use flowscope_core::{TemplateConfig, TemplateMode};
use sqlparser::ast::helpers::attached_token::AttachedToken;
use sqlparser::ast::*;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};
#[cfg(feature = "templating")]
use std::collections::HashMap;
use std::collections::{BTreeMap, HashSet, VecDeque};

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

    pub fn merge(&mut self, other: &Self) {
        for (code, count) in &other.by_rule {
            self.add(code, *count);
        }
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
    pub skipped_counts: FixSkippedCounts,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[must_use]
pub struct FixSkippedCounts {
    pub unsafe_skipped: usize,
    pub protected_range_blocked: usize,
    pub overlap_conflict_blocked: usize,
    pub display_only: usize,
}

#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct FixOptions {
    pub include_unsafe_fixes: bool,
    pub include_rewrite_candidates: bool,
}

impl Default for FixOptions {
    fn default() -> Self {
        Self {
            include_unsafe_fixes: false,
            include_rewrite_candidates: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct RuleFilter {
    disabled: HashSet<String>,
    st005_forbid_subquery_in: St005ForbidSubqueryIn,
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
            st005_forbid_subquery_in,
        }
    }

    fn allows(&self, code: &str) -> bool {
        let canonical =
            canonicalize_rule_code(code).unwrap_or_else(|| code.trim().to_ascii_uppercase());
        !self.disabled.contains(&canonical)
    }

    fn with_rule_disabled(&self, code: &str) -> Self {
        let mut updated = self.clone();
        let canonical =
            canonicalize_rule_code(code).unwrap_or_else(|| code.trim().to_ascii_uppercase());
        updated.disabled.insert(canonical);
        updated
    }
}

/// Apply deterministic lint fixes to a SQL document.
///
/// Notes:
/// - Fixes are planned as localized patches and applied only when non-overlapping.
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
    apply_lint_fixes_with_options(
        sql,
        dialect,
        lint_config,
        FixOptions {
            // Preserve existing behavior for direct/internal callers.
            include_unsafe_fixes: true,
            include_rewrite_candidates: true,
        },
    )
}

pub fn apply_lint_fixes_with_options(
    sql: &str,
    dialect: Dialect,
    lint_config: &LintConfig,
    fix_options: FixOptions,
) -> Result<FixOutcome, ParseError> {
    let rule_filter = RuleFilter::from_lint_config(lint_config);

    let before_issues = lint_issues(sql, dialect, lint_config);
    let before_counts = lint_rule_counts_from_issues(&before_issues);
    let mut core_candidates = build_fix_candidates_from_issue_autofixes(sql, &before_issues);
    core_candidates.extend(build_al001_fallback_candidates(
        sql,
        dialect,
        &before_issues,
        lint_config,
    ));
    let core_autofix_rules =
        collect_core_autofix_rules(&before_issues, fix_options.include_unsafe_fixes);
    let mut candidates = Vec::new();

    if fix_options.include_rewrite_candidates {
        let safe_rule_filter = if fix_options.include_unsafe_fixes {
            rule_filter.clone()
        } else {
            // Structural subquery-to-CTE rewrites are useful but higher risk and
            // therefore opt-in under `--unsafe-fixes`.
            rule_filter.with_rule_disabled(issue_codes::LINT_ST_005)
        };

        let mut statements = parse_sql_with_dialect(sql, dialect)?;
        for stmt in &mut statements {
            fix_statement(stmt, &safe_rule_filter);
        }

        let rewritten_sql = render_statements(&statements, sql);
        let rewritten_sql = if safe_rule_filter.allows(issue_codes::LINT_AL_001) {
            apply_configured_table_alias_style(&rewritten_sql, dialect, lint_config)
        } else {
            preserve_original_table_alias_style(sql, &rewritten_sql, dialect)
        };

        let mut rewrite_candidates = build_fix_candidates_from_rewrite(
            sql,
            &rewritten_sql,
            FixCandidateApplicability::Safe,
            FixCandidateSource::PrimaryRewrite,
        );
        if !fix_options.include_unsafe_fixes {
            let mut unsafe_statements = parse_sql_with_dialect(sql, dialect)?;
            for stmt in &mut unsafe_statements {
                fix_statement(stmt, &rule_filter);
            }
            let unsafe_sql = render_statements(&unsafe_statements, sql);
            let unsafe_sql = if rule_filter.allows(issue_codes::LINT_AL_001) {
                apply_configured_table_alias_style(&unsafe_sql, dialect, lint_config)
            } else {
                preserve_original_table_alias_style(sql, &unsafe_sql, dialect)
            };
            if unsafe_sql != rewritten_sql {
                rewrite_candidates.extend(build_fix_candidates_from_rewrite(
                    sql,
                    &unsafe_sql,
                    FixCandidateApplicability::Unsafe,
                    FixCandidateSource::UnsafeFallback,
                ));
            }
        }

        candidates.extend(rewrite_candidates);
    }

    candidates.extend(core_candidates.iter().cloned());

    let protected_ranges =
        collect_comment_protected_ranges(sql, dialect, !fix_options.include_unsafe_fixes);
    let planned = plan_fix_candidates(
        sql,
        candidates,
        &protected_ranges,
        fix_options.include_unsafe_fixes,
    );
    let mut fixed_sql = apply_planned_edits(sql, &planned.edits);
    let mut after_counts = lint_rule_counts(&fixed_sql, dialect, lint_config);
    let before_total = regression_guard_total(&before_counts);
    let after_total = regression_guard_total(&after_counts);
    let mut skipped_counts = planned.skipped.clone();

    if parse_errors_increased(&before_counts, &after_counts) {
        if let Some(outcome) = try_core_only_fix_plan(
            sql,
            dialect,
            lint_config,
            &before_counts,
            &core_candidates,
            &protected_ranges,
            fix_options.include_unsafe_fixes,
        ) {
            return Ok(outcome);
        }
        if let Some(outcome) = try_incremental_core_fix_plan(
            sql,
            dialect,
            lint_config,
            &before_counts,
            fix_options.include_unsafe_fixes,
        ) {
            return Ok(outcome);
        }

        return Ok(FixOutcome {
            sql: sql.to_string(),
            counts: FixCounts::default(),
            changed: false,
            skipped_due_to_comments: false,
            skipped_due_to_regression: true,
            skipped_counts,
        });
    }

    if fix_options.include_rewrite_candidates
        && core_autofix_rules_not_improved(&before_counts, &after_counts, &core_autofix_rules)
    {
        if let Some(outcome) = try_core_only_fix_plan(
            sql,
            dialect,
            lint_config,
            &before_counts,
            &core_candidates,
            &protected_ranges,
            fix_options.include_unsafe_fixes,
        ) {
            return Ok(outcome);
        }
        if let Some(outcome) = try_incremental_core_fix_plan(
            sql,
            dialect,
            lint_config,
            &before_counts,
            fix_options.include_unsafe_fixes,
        ) {
            return Ok(outcome);
        }
    }

    // Strict regression guard: never apply a fix set that increases total
    // violations, and also retry with core-only planning when net totals are
    // flat but per-rule regressions mask improvements.
    let masked_or_worse = after_total > before_total
        || (after_total == before_total
            && after_counts != before_counts
            && core_autofix_rules_not_improved(&before_counts, &after_counts, &core_autofix_rules));
    if masked_or_worse {
        if let Some(outcome) = try_core_only_fix_plan(
            sql,
            dialect,
            lint_config,
            &before_counts,
            &core_candidates,
            &protected_ranges,
            fix_options.include_unsafe_fixes,
        ) {
            return Ok(outcome);
        }
        if let Some(outcome) = try_incremental_core_fix_plan(
            sql,
            dialect,
            lint_config,
            &before_counts,
            fix_options.include_unsafe_fixes,
        ) {
            return Ok(outcome);
        }

        return Ok(FixOutcome {
            sql: sql.to_string(),
            counts: FixCounts::default(),
            changed: false,
            skipped_due_to_comments: false,
            skipped_due_to_regression: true,
            skipped_counts,
        });
    }

    if !fix_options.include_rewrite_candidates && skipped_counts.overlap_conflict_blocked > 0 {
        if let Some(incremental) = try_incremental_core_fix_plan(
            &fixed_sql,
            dialect,
            lint_config,
            &after_counts,
            fix_options.include_unsafe_fixes,
        ) {
            merge_skipped_counts(&mut skipped_counts, &incremental.skipped_counts);
            fixed_sql = incremental.sql;
            after_counts = lint_rule_counts(&fixed_sql, dialect, lint_config);
        }
    }

    let counts = FixCounts::from_removed(&before_counts, &after_counts);

    if counts.total() == 0 {
        return Ok(FixOutcome {
            sql: sql.to_string(),
            counts,
            changed: false,
            skipped_due_to_comments: false,
            skipped_due_to_regression: false,
            skipped_counts,
        });
    }
    let changed = fixed_sql != sql;

    Ok(FixOutcome {
        sql: fixed_sql,
        counts,
        changed,
        skipped_due_to_comments: false,
        skipped_due_to_regression: false,
        skipped_counts,
    })
}

/// Check whether SQL contains comment markers outside of quoted regions.
#[cfg(test)]
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
    let issues = lint_issues(sql, dialect, lint_config);
    lint_rule_counts_from_issues(&issues)
}

fn lint_issues(sql: &str, dialect: Dialect, lint_config: &LintConfig) -> Vec<Issue> {
    let mut result = analyze(&AnalyzeRequest {
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
    });

    #[cfg(feature = "templating")]
    {
        if contains_template_markers(sql)
            && issues_have_parse_errors(&result.issues)
            && template_retry_enabled_for_fixes(lint_config)
        {
            let jinja_result = analyze(&AnalyzeRequest {
                sql: sql.to_string(),
                files: None,
                dialect,
                source_name: None,
                options: Some(AnalysisOptions {
                    lint: Some(lint_config.clone()),
                    ..Default::default()
                }),
                schema: None,
                template_config: Some(TemplateConfig {
                    mode: TemplateMode::Jinja,
                    context: HashMap::new(),
                }),
            });

            result = if issues_have_template_errors(&jinja_result.issues) {
                analyze(&AnalyzeRequest {
                    sql: sql.to_string(),
                    files: None,
                    dialect,
                    source_name: None,
                    options: Some(AnalysisOptions {
                        lint: Some(lint_config.clone()),
                        ..Default::default()
                    }),
                    schema: None,
                    template_config: Some(TemplateConfig {
                        mode: TemplateMode::Dbt,
                        context: HashMap::new(),
                    }),
                })
            } else {
                jinja_result
            };
        }
    }

    result
        .issues
        .into_iter()
        .filter(|issue| issue.code.starts_with("LINT_") || issue.code == issue_codes::PARSE_ERROR)
        .collect()
}

#[cfg(feature = "templating")]
fn contains_template_markers(sql: &str) -> bool {
    sql.contains("{{") || sql.contains("{%") || sql.contains("{#")
}

#[cfg(feature = "templating")]
fn template_retry_enabled_for_fixes(lint_config: &LintConfig) -> bool {
    let registry_config = LintConfig {
        enabled: true,
        disabled_rules: vec![],
        rule_configs: BTreeMap::new(),
    };
    let enabled_codes: Vec<String> = flowscope_core::linter::rules::all_rules(&registry_config)
        .into_iter()
        .map(|rule| rule.code().to_string())
        .filter(|code| lint_config.is_rule_enabled(code))
        .collect();

    if enabled_codes.len() != 1 {
        return false;
    }

    let only_code = &enabled_codes[0];
    only_code.eq_ignore_ascii_case(issue_codes::LINT_LT_004)
        || only_code.eq_ignore_ascii_case(issue_codes::LINT_LT_007)
        || only_code.eq_ignore_ascii_case(issue_codes::LINT_CP_003)
}

#[cfg(feature = "templating")]
fn issues_have_parse_errors(issues: &[Issue]) -> bool {
    issues
        .iter()
        .any(|issue| issue.code == issue_codes::PARSE_ERROR)
}

#[cfg(feature = "templating")]
fn issues_have_template_errors(issues: &[Issue]) -> bool {
    issues
        .iter()
        .any(|issue| issue.code == issue_codes::TEMPLATE_ERROR)
}

fn lint_rule_counts_from_issues(issues: &[Issue]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for issue in issues {
        *counts.entry(issue.code.clone()).or_insert(0usize) += 1;
    }
    counts
}

fn collect_core_autofix_rules(issues: &[Issue], allow_unsafe: bool) -> HashSet<String> {
    issues
        .iter()
        .filter_map(|issue| {
            let autofix = issue.autofix.as_ref()?;
            let applicable = match autofix.applicability {
                IssueAutofixApplicability::Safe => true,
                IssueAutofixApplicability::Unsafe => allow_unsafe,
                IssueAutofixApplicability::DisplayOnly => false,
            };
            if applicable && core_autofix_conflict_priority(Some(issue.code.as_str())) == 0 {
                Some(issue.code.clone())
            } else {
                None
            }
        })
        .collect()
}

fn core_autofix_rules_not_improved(
    before_counts: &BTreeMap<String, usize>,
    after_counts: &BTreeMap<String, usize>,
    core_autofix_rules: &HashSet<String>,
) -> bool {
    core_autofix_rules.iter().any(|code| {
        let before_count = before_counts.get(code).copied().unwrap_or(0);
        before_count > 0 && after_counts.get(code).copied().unwrap_or(0) >= before_count
    })
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

fn regression_guard_total(counts: &BTreeMap<String, usize>) -> usize {
    counts
        .iter()
        // LT02 parity is currently architectural/out-of-scope; don't let LT02
        // increases mask deterministic improvements in other core autofixes.
        .filter(|(code, _)| !code.eq_ignore_ascii_case(issue_codes::LINT_LT_002))
        .map(|(_, count)| *count)
        .sum()
}

fn try_core_only_fix_plan(
    sql: &str,
    dialect: Dialect,
    lint_config: &LintConfig,
    before_counts: &BTreeMap<String, usize>,
    core_candidates: &[FixCandidate],
    protected_ranges: &[PatchProtectedRange],
    allow_unsafe: bool,
) -> Option<FixOutcome> {
    if core_candidates.is_empty() {
        return None;
    }

    let planned = plan_fix_candidates(
        sql,
        core_candidates.to_vec(),
        protected_ranges,
        allow_unsafe,
    );
    if planned.edits.is_empty() {
        return None;
    }

    let fixed_sql = apply_planned_edits(sql, &planned.edits);
    if fixed_sql == sql {
        return None;
    }

    let after_counts = lint_rule_counts(&fixed_sql, dialect, lint_config);
    if parse_errors_increased(before_counts, &after_counts) {
        return None;
    }

    let counts = FixCounts::from_removed(before_counts, &after_counts);
    let before_total = regression_guard_total(before_counts);
    let after_total = regression_guard_total(&after_counts);
    if counts.total() == 0 || after_total > before_total {
        return None;
    }

    Some(FixOutcome {
        sql: fixed_sql,
        counts,
        changed: true,
        skipped_due_to_comments: false,
        skipped_due_to_regression: false,
        skipped_counts: planned.skipped,
    })
}

fn is_incremental_core_candidate(candidate: &FixCandidate, allow_unsafe: bool) -> bool {
    if candidate.source != FixCandidateSource::CoreAutofix {
        return false;
    }

    if candidate.rule_code.is_none() {
        return false;
    }

    match candidate.applicability {
        FixCandidateApplicability::Safe => true,
        FixCandidateApplicability::Unsafe => allow_unsafe,
        FixCandidateApplicability::DisplayOnly => false,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Al001AliasingPreference {
    Explicit,
    Implicit,
}

fn al001_aliasing_preference(lint_config: &LintConfig) -> Al001AliasingPreference {
    if lint_config
        .rule_option_str(issue_codes::LINT_AL_001, "aliasing")
        .is_some_and(|value| value.eq_ignore_ascii_case("implicit"))
    {
        Al001AliasingPreference::Implicit
    } else {
        Al001AliasingPreference::Explicit
    }
}

fn build_al001_fallback_candidates(
    sql: &str,
    dialect: Dialect,
    issues: &[Issue],
    lint_config: &LintConfig,
) -> Vec<FixCandidate> {
    let fallback_issues: Vec<&Issue> = issues
        .iter()
        .filter(|issue| {
            issue.code.eq_ignore_ascii_case(issue_codes::LINT_AL_001) && issue.span.is_some()
        })
        .collect();
    if fallback_issues.is_empty() {
        return Vec::new();
    }

    let Some(tokens) = alias_tokenize_with_offsets(sql, dialect) else {
        return Vec::new();
    };

    let preference = al001_aliasing_preference(lint_config);
    let mut candidates = Vec::new();
    for issue in fallback_issues {
        let Some(span) = issue.span else {
            continue;
        };
        let alias_start = span.start.min(sql.len());
        let previous_token = tokens
            .iter()
            .rev()
            .find(|token| token.end <= alias_start && !is_alias_trivia_token(&token.token));

        match preference {
            Al001AliasingPreference::Explicit => {
                if previous_token.is_some_and(|token| is_as_token(&token.token)) {
                    continue;
                }
                let replacement = if has_whitespace_before_offset(sql, alias_start) {
                    "AS "
                } else {
                    " AS "
                };
                candidates.push(FixCandidate {
                    start: alias_start,
                    end: alias_start,
                    replacement: replacement.to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::CoreAutofix,
                    rule_code: Some(issue_codes::LINT_AL_001.to_string()),
                });
            }
            Al001AliasingPreference::Implicit => {
                let Some(as_token) = previous_token.filter(|token| is_as_token(&token.token))
                else {
                    continue;
                };
                candidates.push(FixCandidate {
                    start: as_token.start,
                    end: alias_start,
                    replacement: " ".to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::CoreAutofix,
                    rule_code: Some(issue_codes::LINT_AL_001.to_string()),
                });
            }
        }
    }

    candidates
}

fn merge_skipped_counts(total: &mut FixSkippedCounts, current: &FixSkippedCounts) {
    total.unsafe_skipped += current.unsafe_skipped;
    total.protected_range_blocked += current.protected_range_blocked;
    total.overlap_conflict_blocked += current.overlap_conflict_blocked;
    total.display_only += current.display_only;
}

fn try_incremental_core_fix_plan(
    sql: &str,
    dialect: Dialect,
    lint_config: &LintConfig,
    before_counts: &BTreeMap<String, usize>,
    allow_unsafe: bool,
) -> Option<FixOutcome> {
    let mut current_sql = sql.to_string();
    let mut current_counts = before_counts.clone();
    let mut changed = false;
    let mut skipped_counts = FixSkippedCounts::default();
    let mut seen_sql = HashSet::new();
    seen_sql.insert(current_sql.clone());

    const MAX_ITERATIONS: usize = 24;
    for _ in 0..MAX_ITERATIONS {
        let issues = lint_issues(&current_sql, dialect, lint_config);
        let mut all_candidates = build_fix_candidates_from_issue_autofixes(&current_sql, &issues);
        all_candidates.extend(build_al001_fallback_candidates(
            &current_sql,
            dialect,
            &issues,
            lint_config,
        ));
        let candidates = all_candidates
            .into_iter()
            .filter(|candidate| is_incremental_core_candidate(candidate, allow_unsafe))
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            break;
        }

        let mut by_rule: BTreeMap<String, Vec<FixCandidate>> = BTreeMap::new();
        for candidate in candidates {
            if let Some(rule_code) = candidate.rule_code.clone() {
                by_rule.entry(rule_code).or_default().push(candidate);
            }
        }

        if by_rule.is_empty() {
            break;
        }

        let protected_ranges =
            collect_comment_protected_ranges(&current_sql, dialect, !allow_unsafe);
        let current_total = regression_guard_total(&current_counts);

        let mut best_rule: Option<String> = None;
        let mut best_sql: Option<String> = None;
        let mut best_counts: Option<BTreeMap<String, usize>> = None;
        let mut best_removed = 0usize;
        let mut best_after_total = usize::MAX;

        for (rule_code, rule_candidates) in by_rule {
            let planned = plan_fix_candidates(
                &current_sql,
                rule_candidates,
                &protected_ranges,
                allow_unsafe,
            );
            merge_skipped_counts(&mut skipped_counts, &planned.skipped);

            if planned.edits.is_empty() {
                continue;
            }

            let candidate_sql = apply_planned_edits(&current_sql, &planned.edits);
            if candidate_sql == current_sql {
                continue;
            }

            let candidate_counts = lint_rule_counts(&candidate_sql, dialect, lint_config);
            if parse_errors_increased(&current_counts, &candidate_counts) {
                continue;
            }

            let candidate_after_total = regression_guard_total(&candidate_counts);
            if candidate_after_total > current_total {
                continue;
            }

            let candidate_removed =
                FixCounts::from_removed(&current_counts, &candidate_counts).total();
            if candidate_removed == 0 {
                continue;
            }

            let better = candidate_removed > best_removed
                || (candidate_removed == best_removed && candidate_after_total < best_after_total)
                || (candidate_removed == best_removed
                    && candidate_after_total == best_after_total
                    && best_rule
                        .as_ref()
                        .is_none_or(|current_best| rule_code < *current_best));

            if better {
                best_removed = candidate_removed;
                best_after_total = candidate_after_total;
                best_rule = Some(rule_code);
                best_sql = Some(candidate_sql);
                best_counts = Some(candidate_counts);
            }
        }

        let Some(next_sql) = best_sql else {
            break;
        };
        let Some(next_counts) = best_counts else {
            break;
        };
        if !seen_sql.insert(next_sql.clone()) {
            break;
        }

        current_sql = next_sql;
        current_counts = next_counts;
        changed = true;
    }

    if !changed || current_sql == sql {
        return None;
    }

    let final_counts = FixCounts::from_removed(before_counts, &current_counts);
    if final_counts.total() == 0 {
        return None;
    }

    Some(FixOutcome {
        sql: current_sql,
        counts: final_counts,
        changed: true,
        skipped_due_to_comments: false,
        skipped_due_to_regression: false,
        skipped_counts,
    })
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

    let mut desired_by_alias: BTreeMap<String, VecDeque<bool>> = BTreeMap::new();
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

fn apply_configured_table_alias_style(
    sql: &str,
    dialect: Dialect,
    lint_config: &LintConfig,
) -> String {
    let prefer_implicit = matches!(
        al001_aliasing_preference(lint_config),
        Al001AliasingPreference::Implicit
    );
    enforce_table_alias_style(sql, dialect, prefer_implicit)
}

fn enforce_table_alias_style(sql: &str, dialect: Dialect, prefer_implicit: bool) -> String {
    let Some(aliases) = table_alias_occurrences(sql, dialect) else {
        return sql.to_string();
    };

    if prefer_implicit {
        let removals: Vec<(usize, usize)> = aliases
            .into_iter()
            .filter_map(|alias| {
                if alias.explicit_as {
                    alias.as_start.map(|as_start| (as_start, alias.alias_start))
                } else {
                    None
                }
            })
            .collect();
        return apply_byte_removals(sql, removals);
    }

    let insertions: Vec<(usize, &'static str)> = aliases
        .into_iter()
        .filter(|alias| !alias.explicit_as)
        .map(|alias| {
            let insertion = if has_whitespace_before_offset(sql, alias.alias_start) {
                "AS "
            } else {
                " AS "
            };
            (alias.alias_start, insertion)
        })
        .collect();
    apply_byte_insertions(sql, insertions)
}

fn has_whitespace_before_offset(sql: &str, offset: usize) -> bool {
    sql.get(..offset)
        .and_then(|prefix| prefix.chars().next_back())
        .is_some_and(char::is_whitespace)
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

fn apply_byte_insertions(sql: &str, mut insertions: Vec<(usize, &'static str)>) -> String {
    if insertions.is_empty() {
        return sql.to_string();
    }

    insertions.retain(|(offset, _)| *offset <= sql.len());
    if insertions.is_empty() {
        return sql.to_string();
    }

    insertions
        .sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    insertions.dedup_by(|left, right| left.0 == right.0);

    let extra_len: usize = insertions
        .iter()
        .map(|(_, insertion)| insertion.len())
        .sum();
    let mut out = String::with_capacity(sql.len() + extra_len);
    let mut cursor = 0usize;
    for (offset, insertion) in insertions {
        if offset < cursor || offset > sql.len() {
            continue;
        }
        out.push_str(&sql[cursor..offset]);
        out.push_str(insertion);
        cursor = offset;
    }
    out.push_str(&sql[cursor..]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[allow(dead_code)]
enum FixCandidateApplicability {
    Safe,
    Unsafe,
    DisplayOnly,
}

impl FixCandidateApplicability {
    fn sort_key(self) -> u8 {
        match self {
            Self::Safe => 0,
            Self::Unsafe => 1,
            Self::DisplayOnly => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
#[allow(dead_code)]
enum FixCandidateSource {
    PrimaryRewrite,
    CoreAutofix,
    UnsafeFallback,
    DisplayHint,
}

fn core_autofix_conflict_priority(rule_code: Option<&str>) -> u8 {
    let Some(code) = rule_code else {
        return 2;
    };

    if code.eq_ignore_ascii_case(issue_codes::LINT_AM_001)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_001)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AM_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AM_003)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AM_005)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AM_008)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_003)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_004)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_005)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_006)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_007)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_010)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_012)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CP_001)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CP_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CP_003)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CP_004)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CP_005)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AL_001)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AL_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AL_005)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AL_007)
        || code.eq_ignore_ascii_case(issue_codes::LINT_AL_009)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_001)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_003)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_004)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_005)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_006)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_007)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_008)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_009)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_010)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_011)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_012)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_013)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_014)
        || code.eq_ignore_ascii_case(issue_codes::LINT_LT_015)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_001)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_006)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_009)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_005)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_008)
        || code.eq_ignore_ascii_case(issue_codes::LINT_ST_012)
        || code.eq_ignore_ascii_case(issue_codes::LINT_TQ_002)
        || code.eq_ignore_ascii_case(issue_codes::LINT_TQ_003)
        || code.eq_ignore_ascii_case(issue_codes::LINT_RF_003)
        || code.eq_ignore_ascii_case(issue_codes::LINT_RF_004)
        || code.eq_ignore_ascii_case(issue_codes::LINT_CV_011)
        || code.eq_ignore_ascii_case(issue_codes::LINT_RF_006)
        || code.eq_ignore_ascii_case(issue_codes::LINT_JJ_001)
    {
        0
    } else {
        2
    }
}

#[derive(Debug, Clone)]
struct FixCandidate {
    start: usize,
    end: usize,
    replacement: String,
    applicability: FixCandidateApplicability,
    source: FixCandidateSource,
    rule_code: Option<String>,
}

fn fix_candidate_source_priority(candidate: &FixCandidate) -> u8 {
    match candidate.source {
        FixCandidateSource::CoreAutofix => {
            core_autofix_conflict_priority(candidate.rule_code.as_deref())
        }
        FixCandidateSource::PrimaryRewrite => 1,
        FixCandidateSource::UnsafeFallback => 3,
        FixCandidateSource::DisplayHint => 4,
    }
}

#[derive(Debug, Default)]
struct PlannedFixes {
    edits: Vec<PatchEdit>,
    skipped: FixSkippedCounts,
}

fn build_fix_candidates_from_rewrite(
    sql: &str,
    rewritten_sql: &str,
    applicability: FixCandidateApplicability,
    source: FixCandidateSource,
) -> Vec<FixCandidate> {
    if sql == rewritten_sql {
        return Vec::new();
    }

    let mut candidates = derive_localized_span_edits(sql, rewritten_sql)
        .into_iter()
        .map(|edit| FixCandidate {
            start: edit.start,
            end: edit.end,
            replacement: edit.replacement,
            applicability,
            source,
            rule_code: None,
        })
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        candidates.push(FixCandidate {
            start: 0,
            end: sql.len(),
            replacement: rewritten_sql.to_string(),
            applicability,
            source,
            rule_code: None,
        });
    }

    candidates
}

fn build_fix_candidates_from_issue_autofixes(sql: &str, issues: &[Issue]) -> Vec<FixCandidate> {
    let issue_values: Vec<serde_json::Value> = issues
        .iter()
        .filter_map(|issue| serde_json::to_value(issue).ok())
        .collect();
    build_fix_candidates_from_issue_values(sql, &issue_values)
}

fn build_fix_candidates_from_issue_values(
    sql: &str,
    issue_values: &[serde_json::Value],
) -> Vec<FixCandidate> {
    let mut candidates = Vec::new();
    let sql_len = sql.len();

    for issue in issue_values {
        let fallback_span = issue.get("span").and_then(json_span_offsets);
        let issue_rule_code = issue
            .get("code")
            .and_then(serde_json::Value::as_str)
            .map(|code| code.to_string());
        if issue_rule_code
            .as_deref()
            .is_some_and(|code| code.eq_ignore_ascii_case(issue_codes::LINT_AL_001))
        {
            // AL01 core-autofix edits can be malformed in complex statement shapes.
            // We generate robust AL01 candidates from spans separately.
            continue;
        }
        let Some(autofix) = issue.get("autofix").or_else(|| issue.get("autoFix")) else {
            continue;
        };
        collect_issue_autofix_candidates(
            autofix,
            fallback_span,
            sql_len,
            None,
            &issue_rule_code,
            &mut candidates,
        );
    }

    candidates
}

fn collect_issue_autofix_candidates(
    value: &serde_json::Value,
    fallback_span: Option<(usize, usize)>,
    sql_len: usize,
    inherited_applicability: Option<FixCandidateApplicability>,
    issue_rule_code: &Option<String>,
    out: &mut Vec<FixCandidate>,
) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_issue_autofix_candidates(
                    item,
                    fallback_span,
                    sql_len,
                    inherited_applicability,
                    issue_rule_code,
                    out,
                );
            }
        }
        serde_json::Value::Object(_) => {
            let applicability = parse_issue_autofix_applicability(value)
                .or(inherited_applicability)
                .unwrap_or(FixCandidateApplicability::Safe);

            if let Some(edit) = value.get("edit") {
                collect_issue_autofix_candidates(
                    edit,
                    fallback_span,
                    sql_len,
                    Some(applicability),
                    issue_rule_code,
                    out,
                );
            }
            if let Some(edits) = value
                .get("edits")
                .or_else(|| value.get("fixes"))
                .or_else(|| value.get("changes"))
            {
                collect_issue_autofix_candidates(
                    edits,
                    fallback_span,
                    sql_len,
                    Some(applicability),
                    issue_rule_code,
                    out,
                );
            }

            if let Some((start, end)) = parse_issue_autofix_offsets(value, fallback_span) {
                if start <= end
                    && end <= sql_len
                    && value
                        .get("replacement")
                        .or_else(|| value.get("new_text"))
                        .or_else(|| value.get("newText"))
                        .or_else(|| value.get("text"))
                        .and_then(serde_json::Value::as_str)
                        .is_some()
                {
                    let replacement = value
                        .get("replacement")
                        .or_else(|| value.get("new_text"))
                        .or_else(|| value.get("newText"))
                        .or_else(|| value.get("text"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();

                    out.push(FixCandidate {
                        start,
                        end,
                        replacement,
                        applicability,
                        source: FixCandidateSource::CoreAutofix,
                        rule_code: issue_rule_code.clone(),
                    });
                }
            }
        }
        _ => {}
    }
}

fn parse_issue_autofix_offsets(
    value: &serde_json::Value,
    fallback_span: Option<(usize, usize)>,
) -> Option<(usize, usize)> {
    let object = value.as_object()?;

    let mut start = json_usize_field(object, &["start", "start_byte", "startByte"]);
    let mut end = json_usize_field(object, &["end", "end_byte", "endByte"]);

    if let Some((span_start, span_end)) = object.get("span").and_then(json_span_offsets) {
        if start.is_none() {
            start = Some(span_start);
        }
        if end.is_none() {
            end = Some(span_end);
        }
    }

    if let Some((span_start, span_end)) = fallback_span {
        if start.is_none() {
            start = Some(span_start);
        }
        if end.is_none() {
            end = Some(span_end);
        }
    }

    Some((start?, end?))
}

fn json_span_offsets(value: &serde_json::Value) -> Option<(usize, usize)> {
    let object = value.as_object()?;
    let start = json_usize_field(object, &["start", "start_byte", "startByte"])?;
    let end = json_usize_field(object, &["end", "end_byte", "endByte"])?;
    Some((start, end))
}

fn json_usize_field(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<usize> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| {
            value
                .as_u64()
                .and_then(|raw| usize::try_from(raw).ok())
                .or_else(|| value.as_str().and_then(|raw| raw.parse::<usize>().ok()))
        })
    })
}

fn parse_issue_autofix_applicability(
    value: &serde_json::Value,
) -> Option<FixCandidateApplicability> {
    let object = value.as_object()?;

    if object
        .get("display_only")
        .or_else(|| object.get("displayOnly"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Some(FixCandidateApplicability::DisplayOnly);
    }
    if object.get("unsafe").and_then(serde_json::Value::as_bool) == Some(true) {
        return Some(FixCandidateApplicability::Unsafe);
    }

    let text = object
        .get("applicability")
        .or_else(|| object.get("safety"))
        .or_else(|| object.get("kind"))
        .or_else(|| object.get("mode"))
        .and_then(serde_json::Value::as_str)?;
    parse_issue_autofix_applicability_text(text)
}

fn parse_issue_autofix_applicability_text(text: &str) -> Option<FixCandidateApplicability> {
    match text.trim().to_ascii_lowercase().as_str() {
        "safe" => Some(FixCandidateApplicability::Safe),
        "unsafe" => Some(FixCandidateApplicability::Unsafe),
        "display_only" | "display-only" | "displayonly" | "display" | "hint" | "suggestion" => {
            Some(FixCandidateApplicability::DisplayOnly)
        }
        _ => None,
    }
}

fn plan_fix_candidates(
    sql: &str,
    mut candidates: Vec<FixCandidate>,
    protected_ranges: &[PatchProtectedRange],
    allow_unsafe: bool,
) -> PlannedFixes {
    if candidates.is_empty() {
        return PlannedFixes::default();
    }

    candidates.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| left.end.cmp(&right.end))
            .then_with(|| {
                left.applicability
                    .sort_key()
                    .cmp(&right.applicability.sort_key())
            })
            .then_with(|| {
                fix_candidate_source_priority(left).cmp(&fix_candidate_source_priority(right))
            })
            .then_with(|| left.rule_code.cmp(&right.rule_code))
            .then_with(|| left.replacement.cmp(&right.replacement))
    });
    candidates.dedup_by(|left, right| {
        left.start == right.start
            && left.end == right.end
            && left.replacement == right.replacement
            && left.applicability == right.applicability
            && left.source == right.source
            && left.rule_code == right.rule_code
    });

    let patch_fixes: Vec<PatchFix> = candidates
        .into_iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let rule_code = candidate
                .rule_code
                .clone()
                .unwrap_or_else(|| format!("PATCH_{:?}_{idx}", candidate.source));
            let source_priority = fix_candidate_source_priority(&candidate);
            let mut fix = PatchFix::new(
                rule_code,
                patch_applicability(candidate.applicability),
                vec![PatchEdit::replace(
                    candidate.start,
                    candidate.end,
                    candidate.replacement,
                )],
            );
            fix.priority = source_priority as i32;
            fix
        })
        .collect();

    let mut allowed = vec![PatchApplicability::Safe];
    if allow_unsafe {
        allowed.push(PatchApplicability::Unsafe);
    }

    let plan = plan_fixes(sql, patch_fixes, &allowed, protected_ranges);
    let mut skipped = FixSkippedCounts::default();
    for blocked in &plan.blocked {
        let reasons = &blocked.reasons;
        if reasons.iter().any(|reason| {
            matches!(
                reason,
                BlockedReason::ApplicabilityNotAllowed {
                    applicability: PatchApplicability::Unsafe
                }
            )
        }) {
            skipped.unsafe_skipped += 1;
            continue;
        }
        if reasons.iter().any(|reason| {
            matches!(
                reason,
                BlockedReason::ApplicabilityNotAllowed {
                    applicability: PatchApplicability::DisplayOnly
                }
            )
        }) {
            skipped.display_only += 1;
            continue;
        }
        if reasons
            .iter()
            .any(|reason| matches!(reason, BlockedReason::TouchesProtectedRange { .. }))
        {
            skipped.protected_range_blocked += 1;
            continue;
        }
        skipped.overlap_conflict_blocked += 1;
    }

    PlannedFixes {
        edits: plan.accepted_edits(),
        skipped,
    }
}

fn patch_applicability(applicability: FixCandidateApplicability) -> PatchApplicability {
    match applicability {
        FixCandidateApplicability::Safe => PatchApplicability::Safe,
        FixCandidateApplicability::Unsafe => PatchApplicability::Unsafe,
        FixCandidateApplicability::DisplayOnly => PatchApplicability::DisplayOnly,
    }
}

fn apply_planned_edits(sql: &str, edits: &[PatchEdit]) -> String {
    apply_patch_edits(sql, edits)
}

fn collect_comment_protected_ranges(
    sql: &str,
    dialect: Dialect,
    strict_safety_mode: bool,
) -> Vec<PatchProtectedRange> {
    if !strict_safety_mode {
        return Vec::new();
    }

    derive_protected_ranges(sql, dialect)
        .into_iter()
        .filter(|range| matches!(range.kind, PatchProtectedRangeKind::TemplateTag))
        .collect()
}

fn derive_localized_span_edits(original: &str, rewritten: &str) -> Vec<SpanEdit> {
    if original == rewritten {
        return Vec::new();
    }

    let original_chars = original.chars().collect::<Vec<_>>();
    let rewritten_chars = rewritten.chars().collect::<Vec<_>>();

    const MAX_DIFF_MATRIX_CELLS: usize = 2_500_000;
    let matrix_cells = (original_chars.len() + 1).saturating_mul(rewritten_chars.len() + 1);
    if matrix_cells > MAX_DIFF_MATRIX_CELLS {
        return vec![SpanEdit::replace(0, original.len(), rewritten)];
    }

    let diff_steps = diff_steps_via_lcs(&original_chars, &rewritten_chars);
    if diff_steps.is_empty() {
        return Vec::new();
    }

    let original_offsets = char_to_byte_offsets(original);
    let rewritten_offsets = char_to_byte_offsets(rewritten);

    let mut edits = Vec::new();
    let mut original_char_idx = 0usize;
    let mut rewritten_char_idx = 0usize;
    let mut step_idx = 0usize;

    while step_idx < diff_steps.len() {
        if matches!(diff_steps[step_idx], DiffStep::Equal) {
            original_char_idx += 1;
            rewritten_char_idx += 1;
            step_idx += 1;
            continue;
        }

        let edit_original_start = original_char_idx;
        let edit_rewritten_start = rewritten_char_idx;

        while step_idx < diff_steps.len() && !matches!(diff_steps[step_idx], DiffStep::Equal) {
            match diff_steps[step_idx] {
                DiffStep::Delete => original_char_idx += 1,
                DiffStep::Insert => rewritten_char_idx += 1,
                DiffStep::Equal => {}
            }
            step_idx += 1;
        }

        let start = original_offsets[edit_original_start];
        let end = original_offsets[original_char_idx];
        let replacement_start = rewritten_offsets[edit_rewritten_start];
        let replacement_end = rewritten_offsets[rewritten_char_idx];
        edits.push(SpanEdit::replace(
            start,
            end,
            &rewritten[replacement_start..replacement_end],
        ));
    }

    edits
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DiffStep {
    Equal,
    Delete,
    Insert,
}

fn diff_steps_via_lcs(original: &[char], rewritten: &[char]) -> Vec<DiffStep> {
    if original.is_empty() {
        return vec![DiffStep::Insert; rewritten.len()];
    }
    if rewritten.is_empty() {
        return vec![DiffStep::Delete; original.len()];
    }

    let cols = rewritten.len() + 1;
    let mut lcs = vec![0u32; (original.len() + 1) * cols];

    for original_idx in 0..original.len() {
        for rewritten_idx in 0..rewritten.len() {
            let cell = (original_idx + 1) * cols + rewritten_idx + 1;
            lcs[cell] = if original[original_idx] == rewritten[rewritten_idx] {
                lcs[original_idx * cols + rewritten_idx] + 1
            } else {
                lcs[original_idx * cols + rewritten_idx + 1]
                    .max(lcs[(original_idx + 1) * cols + rewritten_idx])
            };
        }
    }

    let mut steps_reversed = Vec::with_capacity(original.len() + rewritten.len());
    let mut original_idx = original.len();
    let mut rewritten_idx = rewritten.len();

    while original_idx > 0 || rewritten_idx > 0 {
        if original_idx > 0
            && rewritten_idx > 0
            && original[original_idx - 1] == rewritten[rewritten_idx - 1]
        {
            steps_reversed.push(DiffStep::Equal);
            original_idx -= 1;
            rewritten_idx -= 1;
            continue;
        }

        let left = if rewritten_idx > 0 {
            lcs[original_idx * cols + rewritten_idx - 1]
        } else {
            0
        };
        let up = if original_idx > 0 {
            lcs[(original_idx - 1) * cols + rewritten_idx]
        } else {
            0
        };

        if rewritten_idx > 0 && (original_idx == 0 || left >= up) {
            steps_reversed.push(DiffStep::Insert);
            rewritten_idx -= 1;
        } else if original_idx > 0 {
            steps_reversed.push(DiffStep::Delete);
            original_idx -= 1;
        }
    }

    steps_reversed.reverse();
    steps_reversed
}

fn char_to_byte_offsets(text: &str) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(text.chars().count() + 1);
    offsets.push(0);
    for (idx, ch) in text.char_indices() {
        offsets.push(idx + ch.len_utf8());
    }
    offsets
}

fn table_alias_occurrences(sql: &str, dialect: Dialect) -> Option<Vec<TableAliasOccurrence>> {
    let statements = parse_sql_with_dialect(sql, dialect).ok()?;
    let tokens = alias_tokenize_with_offsets(sql, dialect)?;

    let mut aliases = Vec::new();
    for statement in &statements {
        collect_table_alias_idents_in_statement(statement, &mut |ident| {
            aliases.push(ident.clone())
        });
    }

    let mut occurrences = Vec::with_capacity(aliases.len());
    for alias in aliases {
        let Some((alias_start, _alias_end)) = alias_ident_span_offsets(sql, &alias) else {
            continue;
        };
        let previous_token = tokens
            .iter()
            .rev()
            .find(|token| token.end <= alias_start && !is_alias_trivia_token(&token.token));

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

fn alias_ident_span_offsets(sql: &str, ident: &Ident) -> Option<(usize, usize)> {
    let start = alias_line_col_to_offset(
        sql,
        ident.span.start.line as usize,
        ident.span.start.column as usize,
    )?;
    let end = alias_line_col_to_offset(
        sql,
        ident.span.end.line as usize,
        ident.span.end.column as usize,
    )?;
    Some((start, end))
}

fn is_as_token(token: &Token) -> bool {
    matches!(token, Token::Word(word) if word.value.eq_ignore_ascii_case("AS"))
}

#[derive(Clone)]
struct AliasLocatedToken {
    token: Token,
    start: usize,
    end: usize,
}

fn alias_tokenize_with_offsets(sql: &str, dialect: Dialect) -> Option<Vec<AliasLocatedToken>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let tokens = tokenizer.tokenize_with_location().ok()?;

    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let Some((start, end)) = alias_token_with_span_offsets(sql, &token) else {
            continue;
        };
        out.push(AliasLocatedToken {
            token: token.token,
            start,
            end,
        });
    }

    Some(out)
}

fn alias_token_with_span_offsets(sql: &str, token: &TokenWithSpan) -> Option<(usize, usize)> {
    let start = alias_line_col_to_offset(
        sql,
        token.span.start.line as usize,
        token.span.start.column as usize,
    )?;
    let end = alias_line_col_to_offset(
        sql,
        token.span.end.line as usize,
        token.span.end.column as usize,
    )?;
    Some((start, end))
}

fn alias_line_col_to_offset(sql: &str, line: usize, column: usize) -> Option<usize> {
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

fn is_alias_trivia_token(token: &Token) -> bool {
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
            collect_table_alias_idents_in_query(subquery, visitor)
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => collect_table_alias_idents_in_table_with_joins(table_with_joins, visitor),
        TableFactor::Pivot { table, .. }
        | TableFactor::Unpivot { table, .. }
        | TableFactor::MatchRecognize { table, .. } => {
            collect_table_alias_idents_in_table_factor(table, visitor)
        }
        _ => {}
    }
}

#[cfg(test)]
fn is_ascii_whitespace_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

#[cfg(test)]
fn is_ascii_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

#[cfg(test)]
fn is_ascii_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
fn skip_ascii_whitespace(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && is_ascii_whitespace_byte(bytes[idx]) {
        idx += 1;
    }
    idx
}

#[cfg(test)]
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

#[cfg(test)]
fn is_word_boundary_for_keyword(bytes: &[u8], idx: usize) -> bool {
    idx == 0 || idx >= bytes.len() || !is_ascii_ident_continue(bytes[idx])
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

fn fix_statement(stmt: &mut Statement, rule_filter: &RuleFilter) {
    match stmt {
        Statement::Query(query) => fix_query(query, rule_filter),
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

fn fix_query(query: &mut Query, rule_filter: &RuleFilter) {
    if let Some(with) = query.with.as_mut() {
        for cte in &mut with.cte_tables {
            fix_query(&mut cte.query, rule_filter);
        }
    }

    fix_set_expr(query.body.as_mut(), rule_filter);
    rewrite_simple_derived_subqueries_to_ctes(query, rule_filter);

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
        SetExpr::SetOperation { left, right, .. } => {
            fix_set_expr(left, rule_filter);
            fix_set_expr(right, rule_filter);
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
    for item in &mut select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                fix_expr(expr, rule_filter);
            }
            SelectItem::ExprWithAlias { expr, .. } => {
                fix_expr(expr, rule_filter);
            }
            SelectItem::QualifiedWildcard(SelectItemQualifiedWildcardKind::Expr(expr), _) => {
                fix_expr(expr, rule_filter);
            }
            _ => {}
        }
    }

    for table_with_joins in &mut select.from {
        if rule_filter.allows(issue_codes::LINT_CV_008) {
            rewrite_right_join_to_left(table_with_joins);
        }

        fix_table_factor(&mut table_with_joins.relation, rule_filter);

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

            fix_table_factor(&mut join.relation, rule_filter);
            fix_join_operator(&mut join.join_operator, rule_filter);

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

fn fix_table_factor(relation: &mut TableFactor, rule_filter: &RuleFilter) {
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

            fix_table_factor(&mut table_with_joins.relation, rule_filter);

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

                fix_table_factor(&mut join.relation, rule_filter);
                fix_join_operator(&mut join.join_operator, rule_filter);

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
            fix_table_factor(table, rule_filter);
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
            fix_table_factor(table, rule_filter);
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

fn fix_join_operator(op: &mut JoinOperator, rule_filter: &RuleFilter) {
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

    // CV11 cast-style rewriting is now handled entirely by the core autofix
    // in cv_011.rs, which correctly supports first-seen consistent mode,
    // CONVERT conversions, and chained :: expressions.

    if rule_filter.allows(issue_codes::LINT_ST_004) {
        if let Some(rewritten) = nested_case_rewrite(expr) {
            *expr = rewritten;
        }
    }
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
    use flowscope_core::{
        analyze, issue_codes, AnalysisOptions, AnalyzeRequest, Dialect, LintConfig,
    };

    fn default_lint_config() -> LintConfig {
        LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::new(),
        }
    }

    fn lint_config_keep_only_rule(rule_code: &str, mut config: LintConfig) -> LintConfig {
        let disabled_rules = flowscope_core::linter::rules::all_rules(&default_lint_config())
            .into_iter()
            .map(|rule| rule.code().to_string())
            .filter(|code| !code.eq_ignore_ascii_case(rule_code))
            .collect();
        config.disabled_rules = disabled_rules;
        config
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

    fn lint_rule_count_with_config_in_dialect(
        sql: &str,
        code: &str,
        dialect: Dialect,
        lint_config: &LintConfig,
    ) -> usize {
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

    #[test]
    fn lint_improvements_can_mask_total_violation_regressions() {
        let before = std::collections::BTreeMap::from([
            (issue_codes::LINT_LT_002.to_string(), 2usize),
            (issue_codes::LINT_LT_001.to_string(), 0usize),
        ]);
        let after = std::collections::BTreeMap::from([
            (issue_codes::LINT_LT_002.to_string(), 1usize),
            (issue_codes::LINT_LT_001.to_string(), 2usize),
        ]);
        let removed = FixCounts::from_removed(&before, &after);
        let before_total: usize = before.values().sum();
        let after_total: usize = after.values().sum();

        assert_eq!(
            removed.total(),
            1,
            "a rule-level improvement can still be observed"
        );
        assert!(
            after_total > before_total,
            "strict regression guard must reject net-violation increases"
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
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_LT_011.to_string()],
            rule_configs: std::collections::BTreeMap::new(),
        };
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
            assert_rule_case_with_config(
                sql,
                issue_codes::LINT_AM_002,
                before,
                after,
                fix_count,
                &lint_config,
            );

            if let Some(expected) = expected_text {
                let out = apply_fix_with_config(sql, &lint_config);
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
            // Disable CP_002 so identifier lowercasing does not turn `A` into `a`,
            // which would create a new AL_009 self-alias violation.
            disabled_rules: vec![issue_codes::LINT_CP_002.to_string()],
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
    fn sqlfluff_st002_unnecessary_case_fix_cases() {
        let cases = [
            // Bool coalesce: CASE WHEN cond THEN TRUE ELSE FALSE END → coalesce(cond, false)
            (
                "SELECT CASE WHEN x > 0 THEN true ELSE false END FROM t",
                1,
                0,
                1,
                Some("COALESCE(X > 0, FALSE)"),
            ),
            // Negated bool: CASE WHEN cond THEN FALSE ELSE TRUE END → not coalesce(cond, false)
            (
                "SELECT CASE WHEN x > 0 THEN false ELSE true END FROM t",
                1,
                0,
                1,
                Some("NOT COALESCE(X > 0, FALSE)"),
            ),
            // Null coalesce: CASE WHEN x IS NULL THEN y ELSE x END → coalesce(x, y)
            (
                "SELECT CASE WHEN x IS NULL THEN 0 ELSE x END FROM t",
                1,
                0,
                1,
                Some("COALESCE(X, 0)"),
            ),
            // Not flagged: regular searched CASE (not an unnecessary pattern)
            (
                "SELECT CASE WHEN x = 1 THEN 'a' WHEN x = 2 THEN 'b' END FROM t",
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
                1,
                0,
                None,
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
            if before == after && fix_count == 0 {
                let initial = lint_rule_count(sql, issue_codes::LINT_ST_009);
                assert_eq!(
                    initial,
                    before,
                    "unexpected initial lint count for {} in SQL: {}",
                    issue_codes::LINT_ST_009,
                    sql
                );

                let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix result");
                assert_eq!(
                    fix_count_for_code(&out.counts, issue_codes::LINT_ST_009),
                    0,
                    "unexpected fix count for {} in SQL: {}",
                    issue_codes::LINT_ST_009,
                    sql
                );
                let after_count = lint_rule_count(&out.sql, issue_codes::LINT_ST_009);
                assert_eq!(
                    after_count,
                    after,
                    "unexpected lint count after fix for {}. SQL: {}",
                    issue_codes::LINT_ST_009,
                    out.sql
                );
            } else {
                assert_rule_case(sql, issue_codes::LINT_ST_009, before, after, fix_count);
            }

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
                // After flattening: nested CASE removed, inner WHEN promoted.
                Some("WHEN SPECIES = 'DOG' THEN 'WOOF'"),
            ),
            (
                "SELECT CASE WHEN species = 'Rat' THEN 'Squeak' ELSE CASE WHEN species = 'Dog' THEN 'Woof' WHEN species = 'Mouse' THEN 'Squeak' ELSE 'Other' END END AS sound FROM mytable",
                1,
                0,
                1,
                // Flattened: all inner WHENs promoted, only one END remains.
                Some("WHEN SPECIES = 'MOUSE' THEN 'SQUEAK' ELSE 'OTHER' END AS SOUND"),
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
        let sql = "(SELECT 1)\n";
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
    fn cv010_fix_converts_double_to_single_in_bigquery() {
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "convention.quoted_literals".to_string(),
                serde_json::json!({"preferred_quoted_literal_style": "single_quotes"}),
            )]),
        };
        // In BigQuery, both "abc" and 'abc' are string literals.
        let sql = "SELECT \"abc\"";
        let before = lint_rule_count_with_config_in_dialect(
            sql,
            issue_codes::LINT_CV_010,
            Dialect::Bigquery,
            &lint_config,
        );
        assert_eq!(
            before, 1,
            "CV10 should flag double-quoted string in BigQuery with single_quotes preference"
        );

        let out = apply_lint_fixes_with_lint_config(sql, Dialect::Bigquery, &lint_config)
            .expect("fix result");
        assert!(
            out.sql.contains("'abc'"),
            "expected double-quoted string to be converted to single-quoted: {}",
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
    fn safe_mode_blocks_template_tag_edits_but_applies_non_template_fixes() {
        let sql = "SELECT '{{foo}}' AS templated, COUNT(1) FROM t";
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: false,
                include_rewrite_candidates: true,
            },
        )
        .expect("fix result");

        assert!(
            out.sql.contains("{{foo}}"),
            "template tag bytes should be preserved in safe mode: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "non-template safe fixes should still apply: {}",
            out.sql
        );
        assert!(
            out.skipped_counts.protected_range_blocked > 0,
            "template-tag edits should be blocked in safe mode"
        );
    }

    #[test]
    fn unsafe_mode_allows_template_tag_edits() {
        let sql = "SELECT '{{foo}}' AS templated, COUNT(1) FROM t";
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: true,
            },
        )
        .expect("fix result");

        assert!(
            out.sql.contains("{{ foo }}"),
            "unsafe mode should allow template-tag formatting fixes: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "other fixes should still apply: {}",
            out.sql
        );
    }

    #[test]
    fn comments_are_not_globally_skipped() {
        let sql = "-- keep this comment\nSELECT COUNT(1) FROM t";
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: false,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
        assert!(
            !out.skipped_due_to_comments,
            "comment presence should not skip all fixes"
        );
        assert!(
            out.sql.contains("-- keep this comment"),
            "comment text must be preserved: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "non-comment region should still be fixable: {}",
            out.sql
        );
    }

    #[test]
    fn mysql_hash_comments_are_not_globally_skipped() {
        let sql = "# keep this comment\nSELECT COUNT(1) FROM t";
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Mysql,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: false,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
        assert!(
            !out.skipped_due_to_comments,
            "comment presence should not skip all fixes"
        );
        assert!(
            out.sql.contains("# keep this comment"),
            "comment text must be preserved: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
            "non-comment region should still be fixable: {}",
            out.sql
        );
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
    fn planner_blocks_protected_ranges_and_applies_non_overlapping_edits() {
        let sql = "SELECT '{{foo}}' AS templated, 1";
        let protected = collect_comment_protected_ranges(sql, Dialect::Generic, true);
        let template_idx = sql.find("{{foo}}").expect("template exists");
        let one_idx = sql.rfind('1').expect("digit exists");

        let planned = plan_fix_candidates(
            sql,
            vec![
                FixCandidate {
                    start: template_idx,
                    end: template_idx + "{{foo}}".len(),
                    replacement: String::new(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::PrimaryRewrite,
                    rule_code: None,
                },
                FixCandidate {
                    start: one_idx,
                    end: one_idx + 1,
                    replacement: "2".to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::PrimaryRewrite,
                    rule_code: None,
                },
            ],
            &protected,
            false,
        );

        let applied = apply_planned_edits(sql, &planned.edits);
        assert!(
            applied.contains("{{foo}}"),
            "template span should remain protected: {applied}"
        );
        assert!(
            applied.ends_with("2"),
            "expected non-overlapping edit: {applied}"
        );
        assert_eq!(planned.skipped.protected_range_blocked, 1);
    }

    #[test]
    fn planner_is_deterministic_for_conflicting_candidates() {
        let sql = "SELECT 1";
        let one_idx = sql.rfind('1').expect("digit exists");

        let left_first = plan_fix_candidates(
            sql,
            vec![
                FixCandidate {
                    start: one_idx,
                    end: one_idx + 1,
                    replacement: "9".to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::PrimaryRewrite,
                    rule_code: None,
                },
                FixCandidate {
                    start: one_idx,
                    end: one_idx + 1,
                    replacement: "2".to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::PrimaryRewrite,
                    rule_code: None,
                },
            ],
            &[],
            false,
        );
        let right_first = plan_fix_candidates(
            sql,
            vec![
                FixCandidate {
                    start: one_idx,
                    end: one_idx + 1,
                    replacement: "2".to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::PrimaryRewrite,
                    rule_code: None,
                },
                FixCandidate {
                    start: one_idx,
                    end: one_idx + 1,
                    replacement: "9".to_string(),
                    applicability: FixCandidateApplicability::Safe,
                    source: FixCandidateSource::PrimaryRewrite,
                    rule_code: None,
                },
            ],
            &[],
            false,
        );

        let left_sql = apply_planned_edits(sql, &left_first.edits);
        let right_sql = apply_planned_edits(sql, &right_first.edits);
        assert_eq!(left_sql, "SELECT 2");
        assert_eq!(left_sql, right_sql);
        assert_eq!(left_first.skipped.overlap_conflict_blocked, 1);
        assert_eq!(right_first.skipped.overlap_conflict_blocked, 1);
    }

    #[test]
    fn core_autofix_candidates_are_collected_and_applied() {
        let sql = "SELECT 1";
        let one_idx = sql.rfind('1').expect("digit exists");
        let issues = vec![serde_json::json!({
            "code": issue_codes::LINT_CV_004,
            "span": { "start": one_idx, "end": one_idx + 1 },
            "autofix": {
                "applicability": "safe",
                "edits": [
                    {
                        "start": one_idx,
                        "end": one_idx + 1,
                        "replacement": "2"
                    }
                ]
            }
        })];
        let candidates = build_fix_candidates_from_issue_values(sql, &issues);

        assert_eq!(candidates.len(), 1);
        let planned = plan_fix_candidates(sql, candidates, &[], false);
        let applied = apply_planned_edits(sql, &planned.edits);
        assert_eq!(applied, "SELECT 2");
    }

    #[test]
    fn st002_core_autofix_candidates_apply_cleanly_in_safe_mode() {
        let sql = "SELECT CASE WHEN x > 0 THEN true ELSE false END FROM t\n";
        let issues = lint_issues(sql, Dialect::Generic, &default_lint_config());
        let candidates = build_fix_candidates_from_issue_autofixes(sql, &issues);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.rule_code.as_deref() == Some(issue_codes::LINT_ST_002)),
            "expected ST002 core candidate from lint issues: {candidates:?}"
        );

        let protected = collect_comment_protected_ranges(sql, Dialect::Generic, true);
        let planned = plan_fix_candidates(sql, candidates, &protected, false);
        let applied = apply_planned_edits(sql, &planned.edits);
        assert_eq!(
            applied, "SELECT coalesce(x > 0, false) FROM t\n",
            "unexpected ST002 planned edits with skipped={:?}",
            planned.skipped
        );
    }

    #[test]
    fn incremental_core_plan_applies_st009_even_when_not_top_priority() {
        let sql = "select foo.a, bar.b from foo left join bar on bar.a = foo.a";
        let lint_config = default_lint_config();
        let before_counts = lint_rule_counts(sql, Dialect::Generic, &lint_config);
        assert_eq!(
            before_counts
                .get(issue_codes::LINT_ST_009)
                .copied()
                .unwrap_or(0),
            1
        );

        let out = try_incremental_core_fix_plan(
            sql,
            Dialect::Generic,
            &lint_config,
            &before_counts,
            false,
        )
        .expect("expected incremental ST009 fix");
        assert!(
            out.sql.contains("foo.a = bar.a"),
            "expected ST009 join condition reorder, got: {}",
            out.sql
        );

        let after_counts = lint_rule_counts(&out.sql, Dialect::Generic, &lint_config);
        assert_eq!(
            after_counts
                .get(issue_codes::LINT_ST_009)
                .copied()
                .unwrap_or(0),
            0
        );
    }

    #[test]
    fn cp03_templated_case_emits_core_autofix_candidate() {
        let sql = "SELECT\n    {{ \"greatest(a, b)\" }},\n    GREATEST(i, j)\n";
        let config = lint_config_keep_only_rule(
            issue_codes::LINT_CP_003,
            LintConfig {
                enabled: true,
                disabled_rules: vec![],
                rule_configs: std::collections::BTreeMap::from([(
                    "core".to_string(),
                    serde_json::json!({"ignore_templated_areas": false}),
                )]),
            },
        );
        let issues = lint_issues(sql, Dialect::Ansi, &config);
        assert!(
            issues
                .iter()
                .any(|issue| { issue.code == issue_codes::LINT_CP_003 && issue.autofix.is_some() }),
            "expected CP03 issue with autofix metadata, got issues={issues:?}"
        );

        let candidates = build_fix_candidates_from_issue_autofixes(sql, &issues);
        assert!(
            candidates.iter().any(|candidate| {
                candidate.rule_code.as_deref() == Some(issue_codes::LINT_CP_003)
                    && &sql[candidate.start..candidate.end] == "GREATEST"
                    && candidate.replacement == "greatest"
            }),
            "expected CP03 GREATEST candidate, got candidates={candidates:?}"
        );
    }

    #[test]
    fn planner_prefers_core_autofix_over_rewrite_conflicts() {
        let sql = "SELECT 1";
        let one_idx = sql.rfind('1').expect("digit exists");
        let core_issue = serde_json::json!({
            "code": issue_codes::LINT_CV_004,
            "autofix": {
                "start": one_idx,
                "end": one_idx + 1,
                "replacement": "9",
                "applicability": "safe"
            }
        });
        let core_candidate = build_fix_candidates_from_issue_values(sql, &[core_issue])[0].clone();
        let rewrite_candidate = FixCandidate {
            start: one_idx,
            end: one_idx + 1,
            replacement: "2".to_string(),
            applicability: FixCandidateApplicability::Safe,
            source: FixCandidateSource::PrimaryRewrite,
            rule_code: None,
        };

        let left_first = plan_fix_candidates(
            sql,
            vec![rewrite_candidate.clone(), core_candidate.clone()],
            &[],
            false,
        );
        let right_first =
            plan_fix_candidates(sql, vec![core_candidate, rewrite_candidate], &[], false);

        let left_sql = apply_planned_edits(sql, &left_first.edits);
        let right_sql = apply_planned_edits(sql, &right_first.edits);
        assert_eq!(left_sql, "SELECT 9");
        assert_eq!(left_sql, right_sql);
        assert_eq!(left_first.skipped.overlap_conflict_blocked, 1);
        assert_eq!(right_first.skipped.overlap_conflict_blocked, 1);
    }

    #[test]
    fn rewrite_mode_falls_back_to_core_plan_when_core_rule_is_not_improved() {
        // Consistent mode normalizes to whichever style appears first.
        // `<>` is first, so the fix normalizes `!=` to `<>`.
        let sql = "SELECT * FROM t WHERE a <> b AND c != d";
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: true,
            },
        )
        .expect("fix result");

        assert_eq!(fix_count_for_code(&out.counts, issue_codes::LINT_CV_001), 1);
        assert!(
            out.sql.contains("a <> b"),
            "expected CV001 style fix: {}",
            out.sql
        );
        assert!(
            out.sql.contains("c <> d"),
            "expected CV001 style fix: {}",
            out.sql
        );
        assert!(
            !out.sql.contains("!="),
            "expected no bang-style operator: {}",
            out.sql
        );
    }

    #[test]
    fn core_autofix_applicability_is_mapped_to_existing_planner_logic() {
        let sql = "SELECT 1";
        let one_idx = sql.rfind('1').expect("digit exists");
        let issues = vec![
            serde_json::json!({
                "code": issue_codes::LINT_ST_005,
                "autofix": {
                    "start": one_idx,
                    "end": one_idx + 1,
                    "replacement": "2",
                    "applicability": "unsafe"
                }
            }),
            serde_json::json!({
                "code": issue_codes::LINT_ST_005,
                "autofix": {
                    "start": one_idx,
                    "end": one_idx + 1,
                    "replacement": "3",
                    "applicability": "display_only"
                }
            }),
        ];
        let candidates = build_fix_candidates_from_issue_values(sql, &issues);

        assert_eq!(
            candidates[0].applicability,
            FixCandidateApplicability::Unsafe
        );
        assert_eq!(
            candidates[1].applicability,
            FixCandidateApplicability::DisplayOnly
        );

        let planned_safe = plan_fix_candidates(sql, candidates.clone(), &[], false);
        assert_eq!(apply_planned_edits(sql, &planned_safe.edits), sql);
        assert_eq!(planned_safe.skipped.unsafe_skipped, 1);
        assert_eq!(planned_safe.skipped.display_only, 1);

        let planned_unsafe = plan_fix_candidates(sql, candidates, &[], true);
        assert_eq!(apply_planned_edits(sql, &planned_unsafe.edits), "SELECT 2");
        assert_eq!(planned_unsafe.skipped.display_only, 1);
    }

    #[test]
    fn planner_tracks_unsafe_and_display_only_skips() {
        let sql = "SELECT 1";
        let one_idx = sql.rfind('1').expect("digit exists");
        let planned = plan_fix_candidates(
            sql,
            vec![
                FixCandidate {
                    start: one_idx,
                    end: one_idx + 1,
                    replacement: "2".to_string(),
                    applicability: FixCandidateApplicability::Unsafe,
                    source: FixCandidateSource::UnsafeFallback,
                    rule_code: None,
                },
                FixCandidate {
                    start: 0,
                    end: 0,
                    replacement: String::new(),
                    applicability: FixCandidateApplicability::DisplayOnly,
                    source: FixCandidateSource::DisplayHint,
                    rule_code: None,
                },
            ],
            &[],
            false,
        );
        let applied = apply_planned_edits(sql, &planned.edits);
        assert_eq!(applied, sql);
        assert_eq!(planned.skipped.unsafe_skipped, 1);
        assert_eq!(planned.skipped.display_only, 1);
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
    fn st005_core_autofix_applies_in_unsafe_mode_with_from_config() {
        let sql = "SELECT * FROM (SELECT 1) sub";
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "structure.subquery".to_string(),
                serde_json::json!({"forbid_subquery_in": "from"}),
            )]),
        };

        let fixed = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &lint_config,
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result")
        .sql;
        assert!(
            fixed.to_ascii_uppercase().contains("WITH SUB AS"),
            "expected unsafe core ST005 autofix to rewrite to CTE, got: {fixed}"
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
        let lint_config = LintConfig {
            enabled: true,
            disabled_rules: vec![issue_codes::LINT_AM_005.to_string()],
            rule_configs: std::collections::BTreeMap::new(),
        };
        let sql = "SELECT t.id FROM t JOIN (SELECT id FROM u) sub ON t.id = sub.id";
        assert_rule_case_with_config(sql, issue_codes::LINT_ST_005, 1, 0, 1, &lint_config);

        let out = apply_fix_with_config(sql, &lint_config);
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
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
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
        let out = apply_lint_fixes_with_options(
            "SELECT 1;\n \t ;",
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
        assert_eq!(out.sql.matches(';').count(), 1);
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
        let out = apply_lint_fixes_with_options(
            sql,
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: false,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
        assert!(
            out.sql.contains("'<>'"),
            "string literal should remain unchanged: {}",
            out.sql
        );
        let compact: String = out.sql.chars().filter(|ch| !ch.is_whitespace()).collect();
        let has_c_style = compact.contains("a!=b") && compact.contains("c!=d");
        let has_ansi_style = compact.contains("a<>b") && compact.contains("c<>d");
        assert!(
            has_c_style || has_ansi_style || compact.contains("a<>b") && compact.contains("c!=d"),
            "operator usage outside string literals should remain intact: {}",
            out.sql
        );
    }

    #[test]
    fn spacing_fixes_do_not_rewrite_single_quoted_literals() {
        let operator_fixed = apply_lint_fixes_with_options(
            "SELECT payload->>'id', 'x=y' FROM t",
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: false,
                include_rewrite_candidates: false,
            },
        )
        .expect("operator spacing fix result")
        .sql;
        assert!(
            operator_fixed.contains("'x=y'"),
            "operator spacing must not mutate literals: {operator_fixed}"
        );
        assert!(
            operator_fixed.contains("payload ->>"),
            "operator spacing should still apply: {operator_fixed}"
        );

        let comma_fixed = apply_lint_fixes_with_options(
            "SELECT a,b, 'x,y' FROM t",
            Dialect::Generic,
            &default_lint_config(),
            FixOptions {
                include_unsafe_fixes: false,
                include_rewrite_candidates: false,
            },
        )
        .expect("comma spacing fix result")
        .sql;
        assert!(
            comma_fixed.contains("'x,y'"),
            "comma spacing must not mutate literals: {comma_fixed}"
        );
        assert!(
            !comma_fixed.contains("a,b"),
            "comma spacing should still apply: {comma_fixed}"
        );
    }

    #[test]
    fn keyword_newline_fix_does_not_rewrite_literals_or_quoted_identifiers() {
        let sql = "SELECT COUNT(1), 'hello FROM world', \"x WHERE y\" FROM t WHERE a = 1";
        let fixed = apply_lint_fixes(sql, Dialect::Generic, &[])
            .expect("fix result")
            .sql;
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
    }

    #[test]
    fn cp04_fix_reduces_literal_capitalisation_violations() {
        // Per-identifier: true and False both violate upper → 2 violations, 2 fixes.
        assert_rule_case(
            "SELECT NULL, true, False FROM t",
            issue_codes::LINT_CP_004,
            2,
            0,
            2,
        );
    }

    #[test]
    fn cp05_fix_reduces_type_capitalisation_violations() {
        // Per-identifier: VarChar violates upper (INT is already correct) → 1 violation.
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
    fn lt04_fix_moves_comma_around_templated_columns_in_ansi() {
        let leading_sql = "SELECT\n    c1,\n    {{ \"c2\" }} AS days_since\nFROM logs";
        let leading_config = lint_config_keep_only_rule(
            issue_codes::LINT_LT_004,
            LintConfig {
                enabled: true,
                disabled_rules: vec![],
                rule_configs: std::collections::BTreeMap::from([(
                    "layout.commas".to_string(),
                    serde_json::json!({"line_position": "leading"}),
                )]),
            },
        );
        let leading_issues = lint_issues(leading_sql, Dialect::Ansi, &leading_config);
        let leading_lt04 = leading_issues
            .iter()
            .find(|issue| issue.code == issue_codes::LINT_LT_004)
            .expect("expected LT04 issue before fix");
        assert!(
            leading_lt04.autofix.is_some(),
            "expected LT04 issue to carry autofix metadata in fix pipeline"
        );
        let leading_out = apply_lint_fixes_with_options(
            leading_sql,
            Dialect::Ansi,
            &leading_config,
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
        assert!(
            !leading_out.skipped_due_to_regression,
            "LT04 leading templated fix should not be treated as regression"
        );
        assert_eq!(
            leading_out.sql,
            "SELECT\n    c1\n    , {{ \"c2\" }} AS days_since\nFROM logs"
        );

        let trailing_sql = "SELECT\n    {{ \"c1\" }}\n    , c2 AS days_since\nFROM logs";
        let trailing_config =
            lint_config_keep_only_rule(issue_codes::LINT_LT_004, default_lint_config());
        let trailing_out = apply_lint_fixes_with_options(
            trailing_sql,
            Dialect::Ansi,
            &trailing_config,
            FixOptions {
                include_unsafe_fixes: true,
                include_rewrite_candidates: false,
            },
        )
        .expect("fix result");
        assert!(
            !trailing_out.skipped_due_to_regression,
            "LT04 trailing templated fix should not be treated as regression"
        );
        assert_eq!(
            trailing_out.sql,
            "SELECT\n    {{ \"c1\" }},\n    c2 AS days_since\nFROM logs"
        );
    }
    #[test]
    fn rf004_core_autofix_respects_rule_filter() {
        let sql = "select a from users as select\n";

        let out_rf_disabled = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_RF_004.to_string()],
        )
        .expect("fix result");
        assert_eq!(
            out_rf_disabled.sql, sql,
            "excluding RF_004 should block alias-keyword core autofix"
        );

        let out_al_disabled = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_AL_005.to_string()],
        )
        .expect("fix result");
        assert!(
            out_al_disabled.sql.contains("alias_select"),
            "excluding AL_005 must not block RF_004 core autofix: {}",
            out_al_disabled.sql
        );
    }

    #[test]
    fn rf003_core_autofix_respects_rule_filter() {
        let sql = "select a.id, id2 from a\n";

        let out_rf_disabled = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_RF_003.to_string()],
        )
        .expect("fix result");
        assert_eq!(
            out_rf_disabled.sql, sql,
            "excluding RF_003 should block reference qualification core autofix"
        );

        let out_al_disabled = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_AL_005.to_string()],
        )
        .expect("fix result");
        assert!(
            out_al_disabled.sql.contains("a.id2"),
            "excluding AL_005 must not block RF_003 core autofix: {}",
            out_al_disabled.sql
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
    fn table_alias_occurrences_handles_with_insert_select_aliases() {
        let sql = r#"
WITH params AS (
    SELECT now() - interval '1 day' AS period_start, now() AS period_end
),
overall AS (
    SELECT route, nav_type, mark FROM metrics.page_performance
),
device_breakdown AS (
    SELECT route, nav_type, mark FROM (
        SELECT route, nav_type, mark FROM metrics.page_performance
    ) sub
),
network_breakdown AS (
    SELECT route, nav_type, mark FROM (
        SELECT route, nav_type, mark FROM metrics.page_performance
    ) sub
),
version_breakdown AS (
    SELECT route, nav_type, mark FROM (
        SELECT route, nav_type, mark FROM metrics.page_performance
    ) sub
)
INSERT INTO metrics.page_performance_summary (route, period_start, period_end, nav_type, mark)
SELECT o.route, p.period_start, p.period_end, o.nav_type, o.mark
FROM overall o
CROSS JOIN params p
LEFT JOIN device_breakdown d ON d.route = o.route
LEFT JOIN network_breakdown n ON n.route = o.route
LEFT JOIN version_breakdown v ON v.route = o.route
ON CONFLICT (route, period_start, nav_type, mark) DO UPDATE SET
    period_end = EXCLUDED.period_end;
"#;

        let occurrences = table_alias_occurrences(sql, Dialect::Postgres)
            .expect("alias occurrences should parse");
        let implicit_count = occurrences
            .iter()
            .filter(|alias| !alias.explicit_as)
            .count();
        assert!(
            implicit_count >= 8,
            "expected implicit aliases in CTE+INSERT query, got {}: {:?}",
            implicit_count,
            occurrences
                .iter()
                .map(|alias| (&alias.alias_key, alias.explicit_as))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn excluded_rule_is_not_rewritten_when_other_rules_are_fixed() {
        let sql = "SELECT COUNT(1) FROM t WHERE a<>b";
        let disabled = vec![issue_codes::LINT_CV_001.to_string()];
        let out = apply_lint_fixes(sql, Dialect::Generic, &disabled).expect("fix result");
        assert!(
            out.sql.to_ascii_uppercase().contains("COUNT(*)"),
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
    fn references_quoting_fix_unquotes_case_insensitive_dialect() {
        // In a case-insensitive dialect (Generic), mixed-case quoted identifiers
        // are unnecessarily quoted because case doesn't matter.
        let sql = "SELECT \"CamelCase\" FROM t UNION SELECT 2";
        let out = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_LT_011.to_string()],
        )
        .expect("fix result");
        assert!(
            out.sql.contains("CamelCase") && !out.sql.contains("\"CamelCase\""),
            "case-insensitive dialect should unquote: {}",
            out.sql
        );
        assert!(
            out.sql.to_ascii_uppercase().contains("DISTINCT SELECT"),
            "expected another fix to persist output: {}",
            out.sql
        );
    }

    #[test]
    fn references_quoting_fix_keeps_case_sensitive_identifier_quotes() {
        // In Postgres (lowercase casefold), mixed-case identifiers must stay
        // quoted because unquoting would fold to lowercase.
        let sql = "SELECT \"CamelCase\" FROM t UNION SELECT 2";
        let out = apply_lint_fixes(
            sql,
            Dialect::Postgres,
            &[issue_codes::LINT_LT_011.to_string()],
        )
        .expect("fix result");
        assert!(
            out.sql.contains("\"CamelCase\""),
            "case-sensitive identifier must remain quoted: {}",
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
            (issue_codes::LINT_CP_002, "SELECT Col, col FROM t"),
            (issue_codes::LINT_CP_003, "SELECT COUNT(*), count(name) FROM t"),
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
            (
                issue_codes::LINT_CV_012,
                "SELECT a.x, b.y FROM a JOIN b WHERE a.id = b.id",
            ),
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
                "SELECT CASE WHEN x > 0 THEN true ELSE false END FROM t",
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

    // --- CV_012: implicit WHERE join → explicit ON ---

    #[test]
    fn cv012_simple_where_join_to_on() {
        let sql = "SELECT a.x, b.y FROM a JOIN b WHERE a.id = b.id";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix");
        let lower = out.sql.to_ascii_lowercase();
        assert!(
            lower.contains(" on ") && !lower.contains("where"),
            "expected JOIN ON without WHERE: {}",
            out.sql
        );
    }

    #[test]
    fn cv012_mixed_where_keeps_non_join_predicates() {
        let sql = "SELECT a.x FROM a JOIN b WHERE a.id = b.id AND a.val > 10";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix");
        let lower = out.sql.to_ascii_lowercase();
        assert!(lower.contains(" on "), "expected JOIN ON: {}", out.sql);
        assert!(
            lower.contains("where"),
            "expected remaining WHERE: {}",
            out.sql
        );
    }

    #[test]
    fn cv012_multi_join_chain() {
        let sql = "SELECT * FROM a JOIN b JOIN c WHERE a.id = b.id AND b.id = c.id";
        let out = apply_lint_fixes(
            sql,
            Dialect::Generic,
            &[issue_codes::LINT_AM_005.to_string()],
        )
        .expect("fix");
        let lower = out.sql.to_ascii_lowercase();
        // Both joins should get ON clauses.
        let on_count = lower.matches(" on ").count();
        assert!(on_count >= 2, "expected at least 2 ON clauses: {}", out.sql);
        assert!(
            !lower.contains("where"),
            "all predicates should be extracted: {}",
            out.sql
        );
    }

    #[test]
    fn cv012_preserves_explicit_on() {
        let sql = "SELECT * FROM a JOIN b ON a.id = b.id";
        let out = apply_lint_fixes(sql, Dialect::Generic, &[]).expect("fix");
        assert_eq!(
            lint_rule_count(sql, issue_codes::LINT_CV_012),
            0,
            "explicit ON should not trigger CV_012"
        );
        let lower = out.sql.to_ascii_lowercase();
        assert!(
            lower.contains("on a.id = b.id"),
            "ON clause should be preserved: {}",
            out.sql
        );
    }

    #[test]
    fn cv012_idempotent() {
        let sql = "SELECT a.x, b.y FROM a JOIN b WHERE a.id = b.id";
        let disabled = vec![issue_codes::LINT_LT_014.to_string()];
        let out1 = apply_lint_fixes(sql, Dialect::Generic, &disabled).expect("fix");
        let out2 = apply_lint_fixes(&out1.sql, Dialect::Generic, &disabled).expect("fix2");
        assert_eq!(
            out1.sql.trim_end(),
            out2.sql.trim_end(),
            "second pass should be idempotent aside from trailing-whitespace normalization"
        );
    }
}
