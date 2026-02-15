//! LINT_AL_001: Table alias style.
//!
//! SQLFluff parity: configurable table aliasing style (`explicit`/`implicit`).

use crate::linter::config::LintConfig;
use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Dialect, Issue, IssueAutofixApplicability, IssuePatchEdit, Span};
use sqlparser::ast::{Ident, Query, SetExpr, Statement, TableFactor, TableWithJoins};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer, Whitespace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AliasingPreference {
    Explicit,
    Implicit,
}

impl AliasingPreference {
    fn from_config(config: &LintConfig, rule_code: &str) -> Self {
        match config
            .rule_option_str(rule_code, "aliasing")
            .unwrap_or("explicit")
            .to_ascii_lowercase()
            .as_str()
        {
            "implicit" => Self::Implicit,
            _ => Self::Explicit,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Explicit => "Use explicit AS when aliasing tables.",
            Self::Implicit => "Use implicit aliasing when aliasing tables (omit AS).",
        }
    }

    fn violation(self, explicit_as: bool) -> bool {
        match self {
            Self::Explicit => !explicit_as,
            Self::Implicit => explicit_as,
        }
    }
}

pub struct AliasingTableStyle {
    aliasing: AliasingPreference,
}

impl AliasingTableStyle {
    pub fn from_config(config: &LintConfig) -> Self {
        Self {
            aliasing: AliasingPreference::from_config(config, issue_codes::LINT_AL_001),
        }
    }
}

impl Default for AliasingTableStyle {
    fn default() -> Self {
        Self {
            aliasing: AliasingPreference::Explicit,
        }
    }
}

impl LintRule for AliasingTableStyle {
    fn code(&self) -> &'static str {
        issue_codes::LINT_AL_001
    }

    fn name(&self) -> &'static str {
        "Table alias style"
    }

    fn description(&self) -> &'static str {
        "Implicit/explicit aliasing of table."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let mut issues = Vec::new();
        let tokens =
            tokenized_for_context(ctx).or_else(|| tokenized(ctx.statement_sql(), ctx.dialect()));

        collect_table_aliases_in_statement(statement, &mut |alias| {
            let Some(occurrence) = alias_occurrence_in_statement(alias, ctx, tokens.as_deref())
            else {
                return;
            };

            if !self.aliasing.violation(occurrence.explicit_as) {
                return;
            }

            let mut issue = Issue::warning(issue_codes::LINT_AL_001, self.aliasing.message())
                .with_statement(ctx.statement_index)
                .with_span(ctx.span_from_statement_offset(occurrence.start, occurrence.end));
            if let Some(edits) = autofix_edits_for_occurrence(occurrence, self.aliasing) {
                issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, edits);
            }

            issues.push(issue);
        });

        issues
    }
}

#[derive(Clone, Copy)]
struct AliasOccurrence {
    start: usize,
    end: usize,
    explicit_as: bool,
    as_span: Option<Span>,
    /// Whether there is whitespace before the alias position.
    has_leading_whitespace: bool,
}

fn autofix_edits_for_occurrence(
    occurrence: AliasOccurrence,
    aliasing: AliasingPreference,
) -> Option<Vec<IssuePatchEdit>> {
    match aliasing {
        AliasingPreference::Explicit if !occurrence.explicit_as => {
            let insert = Span::new(occurrence.start, occurrence.start);
            let replacement = if occurrence.has_leading_whitespace {
                "AS "
            } else {
                " AS "
            };
            Some(vec![IssuePatchEdit::new(insert, replacement)])
        }
        AliasingPreference::Implicit if occurrence.explicit_as => {
            let as_span = occurrence.as_span?;
            // Replace " AS " (leading whitespace + AS keyword + trailing whitespace)
            // with a single space to preserve separation between table name and alias.
            let delete_end = occurrence.start;
            Some(vec![IssuePatchEdit::new(
                Span::new(as_span.start, delete_end),
                " ",
            )])
        }
        _ => None,
    }
}

fn alias_occurrence_in_statement(
    alias: &Ident,
    ctx: &LintContext,
    tokens: Option<&[LocatedToken]>,
) -> Option<AliasOccurrence> {
    let tokens = tokens?;

    let abs_start = line_col_to_offset(
        ctx.sql,
        alias.span.start.line as usize,
        alias.span.start.column as usize,
    )?;
    let abs_end = line_col_to_offset(
        ctx.sql,
        alias.span.end.line as usize,
        alias.span.end.column as usize,
    )?;

    if abs_start < ctx.statement_range.start || abs_end > ctx.statement_range.end {
        return None;
    }

    let rel_start = abs_start - ctx.statement_range.start;
    let rel_end = abs_end - ctx.statement_range.start;
    let (explicit_as, as_span) = explicit_as_before_alias_tokens(tokens, rel_start)?;
    let has_leading_whitespace = has_whitespace_before(tokens, rel_start);
    Some(AliasOccurrence {
        start: rel_start,
        end: rel_end,
        explicit_as,
        as_span,
        has_leading_whitespace,
    })
}

fn collect_table_aliases_in_statement<F: FnMut(&Ident)>(statement: &Statement, visitor: &mut F) {
    match statement {
        Statement::Query(query) => collect_table_aliases_in_query(query, visitor),
        Statement::Insert(insert) => {
            if let Some(source) = &insert.source {
                collect_table_aliases_in_query(source, visitor);
            }
        }
        Statement::CreateView { query, .. } => collect_table_aliases_in_query(query, visitor),
        Statement::CreateTable(create) => {
            if let Some(query) = &create.query {
                collect_table_aliases_in_query(query, visitor);
            }
        }
        Statement::Merge { table, source, .. } => {
            collect_table_aliases_in_table_factor(table, visitor);
            collect_table_aliases_in_table_factor(source, visitor);
        }
        _ => {}
    }
}

fn collect_table_aliases_in_query<F: FnMut(&Ident)>(query: &Query, visitor: &mut F) {
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            collect_table_aliases_in_query(&cte.query, visitor);
        }
    }

    collect_table_aliases_in_set_expr(&query.body, visitor);
}

fn collect_table_aliases_in_set_expr<F: FnMut(&Ident)>(set_expr: &SetExpr, visitor: &mut F) {
    match set_expr {
        SetExpr::Select(select) => {
            for table in &select.from {
                collect_table_aliases_in_table_with_joins(table, visitor);
            }
        }
        SetExpr::Query(query) => collect_table_aliases_in_query(query, visitor),
        SetExpr::SetOperation { left, right, .. } => {
            collect_table_aliases_in_set_expr(left, visitor);
            collect_table_aliases_in_set_expr(right, visitor);
        }
        SetExpr::Insert(statement)
        | SetExpr::Update(statement)
        | SetExpr::Delete(statement)
        | SetExpr::Merge(statement) => collect_table_aliases_in_statement(statement, visitor),
        _ => {}
    }
}

fn collect_table_aliases_in_table_with_joins<F: FnMut(&Ident)>(
    table_with_joins: &TableWithJoins,
    visitor: &mut F,
) {
    collect_table_aliases_in_table_factor(&table_with_joins.relation, visitor);
    for join in &table_with_joins.joins {
        collect_table_aliases_in_table_factor(&join.relation, visitor);
    }
}

fn collect_table_aliases_in_table_factor<F: FnMut(&Ident)>(
    table_factor: &TableFactor,
    visitor: &mut F,
) {
    if let Some(alias) = table_factor_alias_ident(table_factor) {
        visitor(alias);
    }

    match table_factor {
        TableFactor::Derived { subquery, .. } => collect_table_aliases_in_query(subquery, visitor),
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => collect_table_aliases_in_table_with_joins(table_with_joins, visitor),
        TableFactor::Pivot { table, .. }
        | TableFactor::Unpivot { table, .. }
        | TableFactor::MatchRecognize { table, .. } => {
            collect_table_aliases_in_table_factor(table, visitor)
        }
        _ => {}
    }
}

fn table_factor_alias_ident(table_factor: &TableFactor) -> Option<&Ident> {
    let alias = match table_factor {
        TableFactor::Table { alias, .. }
        | TableFactor::Derived { alias, .. }
        | TableFactor::TableFunction { alias, .. }
        | TableFactor::Function { alias, .. }
        | TableFactor::UNNEST { alias, .. }
        | TableFactor::JsonTable { alias, .. }
        | TableFactor::OpenJsonTable { alias, .. }
        | TableFactor::NestedJoin { alias, .. }
        | TableFactor::Pivot { alias, .. }
        | TableFactor::Unpivot { alias, .. }
        | TableFactor::MatchRecognize { alias, .. }
        | TableFactor::XmlTable { alias, .. }
        | TableFactor::SemanticView { alias, .. } => alias.as_ref(),
    }?;

    Some(&alias.name)
}

fn explicit_as_before_alias_tokens(
    tokens: &[LocatedToken],
    alias_start: usize,
) -> Option<(bool, Option<Span>)> {
    let token = tokens
        .iter()
        .rev()
        .find(|token| token.end <= alias_start && !is_trivia_token(&token.token))?;
    if is_as_token(&token.token) {
        // Look for leading whitespace before AS to include in the span.
        let leading_ws_start = tokens
            .iter()
            .rev()
            .find(|t| t.end <= token.start && !is_trivia_token(&t.token))
            .map(|t| t.end)
            .unwrap_or(token.start);
        Some((true, Some(Span::new(leading_ws_start, token.end))))
    } else {
        Some((false, None))
    }
}

/// Checks if there is whitespace immediately before the given position.
fn has_whitespace_before(tokens: &[LocatedToken], pos: usize) -> bool {
    tokens
        .iter()
        .rev()
        .find(|t| t.end <= pos)
        .is_some_and(|t| is_trivia_token(&t.token))
}

fn is_as_token(token: &Token) -> bool {
    match token {
        Token::Word(word) => word.value.eq_ignore_ascii_case("AS"),
        _ => false,
    }
}

#[derive(Clone)]
struct LocatedToken {
    token: Token,
    start: usize,
    end: usize,
}

fn tokenized(sql: &str, dialect: Dialect) -> Option<Vec<LocatedToken>> {
    let dialect = dialect.to_sqlparser_dialect();
    let mut tokenizer = Tokenizer::new(dialect.as_ref(), sql);
    let tokens = tokenizer.tokenize_with_location().ok()?;

    let mut out = Vec::with_capacity(tokens.len());
    for token in tokens {
        let (start, end) = token_with_span_offsets(sql, &token)?;
        out.push(LocatedToken {
            token: token.token,
            start,
            end,
        });
    }
    Some(out)
}

fn tokenized_for_context(ctx: &LintContext) -> Option<Vec<LocatedToken>> {
    let statement_start = ctx.statement_range.start;
    ctx.with_document_tokens(|tokens| {
        if tokens.is_empty() {
            return None;
        }

        Some(
            tokens
                .iter()
                .filter_map(|token| {
                    let (start, end) = token_with_span_offsets(ctx.sql, token)?;
                    if start < ctx.statement_range.start || end > ctx.statement_range.end {
                        return None;
                    }
                    Some(LocatedToken {
                        token: token.token.clone(),
                        start: start - statement_start,
                        end: end - statement_start,
                    })
                })
                .collect::<Vec<_>>(),
        )
    })
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
    use crate::{
        parser::{parse_sql, parse_sql_with_dialect},
        types::IssueAutofixApplicability,
        Dialect,
    };

    fn run_with_rule(sql: &str, rule: AliasingTableStyle) -> Vec<Issue> {
        let stmts = parse_sql(sql).expect("parse");
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

    fn run(sql: &str) -> Vec<Issue> {
        run_with_rule(sql, AliasingTableStyle::default())
    }

    #[test]
    fn flags_implicit_table_aliases() {
        let issues = run("select * from users u join orders o on u.id = o.user_id");
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(|i| i.code == issue_codes::LINT_AL_001));
    }

    #[test]
    fn allows_explicit_as_table_aliases() {
        let issues = run("select * from users as u join orders as o on u.id = o.user_id");
        assert!(issues.is_empty());
    }

    #[test]
    fn flags_explicit_aliases_when_implicit_policy_requested() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_AL_001".to_string(),
                serde_json::json!({"aliasing": "implicit"}),
            )]),
        };
        let issues = run_with_rule(
            "select * from users as u join orders as o on u.id = o.user_id",
            AliasingTableStyle::from_config(&config),
        );
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn flags_implicit_derived_table_alias() {
        let issues = run("select * from (select 1) d");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_AL_001);
    }

    #[test]
    fn flags_implicit_merge_aliases_in_bigquery() {
        let sql = "MERGE dataset.inventory t USING dataset.newarrivals s ON t.product = s.product WHEN MATCHED THEN UPDATE SET quantity = t.quantity + s.quantity";
        let statements = parse_sql_with_dialect(sql, Dialect::Bigquery).expect("parse");
        let issues = statements
            .iter()
            .enumerate()
            .flat_map(|(index, stmt)| {
                AliasingTableStyle::default().check(
                    stmt,
                    &LintContext {
                        sql,
                        statement_range: 0..sql.len(),
                        statement_index: index,
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(|i| i.code == issue_codes::LINT_AL_001));
    }

    #[test]
    fn explicit_mode_emits_safe_insert_as_autofix_patch() {
        let sql = "select * from users u";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected AL001 core autofix metadata in explicit mode");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        assert_eq!(autofix.edits[0].replacement, "AS ");
        assert_eq!(autofix.edits[0].span.start, autofix.edits[0].span.end);
    }

    #[test]
    fn implicit_mode_emits_safe_remove_as_autofix_patch() {
        let config = LintConfig {
            enabled: true,
            disabled_rules: vec![],
            rule_configs: std::collections::BTreeMap::from([(
                "LINT_AL_001".to_string(),
                serde_json::json!({"aliasing": "implicit"}),
            )]),
        };
        let rule = AliasingTableStyle::from_config(&config);
        let sql = "select * from users as u";
        let issues = run_with_rule(sql, rule);
        assert_eq!(issues.len(), 1);

        let autofix = issues[0]
            .autofix
            .as_ref()
            .expect("expected AL001 core autofix metadata in implicit mode");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        assert_eq!(autofix.edits.len(), 1);
        assert_eq!(autofix.edits[0].replacement, " ");
        // Span should cover " as " (leading whitespace + AS keyword + trailing whitespace).
        assert_eq!(
            &sql[autofix.edits[0].span.start..autofix.edits[0].span.end],
            " as "
        );
    }
}
