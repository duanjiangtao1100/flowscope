//! LINT_TQ_002: TSQL procedure BEGIN/END block.
//!
//! SQLFluff TQ02 parity (current scope): `CREATE PROCEDURE` should include a
//! `BEGIN`/`END` block.

use crate::linter::rule::{LintContext, LintRule};
use crate::types::{issue_codes, Issue, IssueAutofixApplicability, IssuePatchEdit};
use sqlparser::ast::{ConditionalStatements, Statement};

pub struct TsqlProcedureBeginEnd;

impl LintRule for TsqlProcedureBeginEnd {
    fn code(&self) -> &'static str {
        issue_codes::LINT_TQ_002
    }

    fn name(&self) -> &'static str {
        "TSQL procedure BEGIN/END"
    }

    fn description(&self) -> &'static str {
        "Procedure bodies with multiple statements should be wrapped in BEGIN/END."
    }

    fn check(&self, statement: &Statement, ctx: &LintContext) -> Vec<Issue> {
        let has_violation = match statement {
            Statement::CreateProcedure { body, .. } => !procedure_body_uses_begin_end(body),
            _ => false,
        };

        if has_violation {
            let mut issue = Issue::warning(
                issue_codes::LINT_TQ_002,
                "CREATE PROCEDURE should include BEGIN/END block.",
            )
            .with_statement(ctx.statement_index);

            let autofix_edits = tq002_autofix_edits(ctx.statement_sql())
                .into_iter()
                .map(|edit| {
                    IssuePatchEdit::new(
                        ctx.span_from_statement_offset(edit.start, edit.end),
                        edit.replacement,
                    )
                })
                .collect::<Vec<_>>();
            if !autofix_edits.is_empty() {
                issue = issue.with_autofix_edits(IssueAutofixApplicability::Safe, autofix_edits);
            }

            vec![issue]
        } else {
            Vec::new()
        }
    }
}

struct Tq002AutofixEdit {
    start: usize,
    end: usize,
    replacement: String,
}

fn tq002_autofix_edits(sql: &str) -> Vec<Tq002AutofixEdit> {
    let Some((body_start, tail, final_semicolon)) = procedure_body_offsets(sql) else {
        return Vec::new();
    };

    let mut edits = vec![Tq002AutofixEdit {
        start: body_start,
        end: body_start,
        replacement: "BEGIN ".to_string(),
    }];

    if let Some(semicolon_index) = final_semicolon {
        edits.push(Tq002AutofixEdit {
            start: semicolon_index,
            end: semicolon_index + 1,
            replacement: "; END;".to_string(),
        });
    } else {
        edits.push(Tq002AutofixEdit {
            start: tail,
            end: tail,
            replacement: "; END".to_string(),
        });
    }

    edits
}

fn procedure_body_offsets(sql: &str) -> Option<(usize, usize, Option<usize>)> {
    let bytes = sql.as_bytes();
    let mut index = skip_ascii_whitespace(bytes, 0);

    let create_end = match_ascii_keyword_at(bytes, index, b"CREATE")?;
    index = skip_ascii_whitespace(bytes, create_end);
    let proc_end = match_ascii_keyword_at(bytes, index, b"PROC")
        .or_else(|| match_ascii_keyword_at(bytes, index, b"PROCEDURE"))?;

    let name_start = skip_ascii_whitespace(bytes, proc_end);
    let name_end = consume_ascii_identifier(bytes, name_start)?;

    let as_start = skip_ascii_whitespace(bytes, name_end);
    let as_end = match_ascii_keyword_at(bytes, as_start, b"AS")?;

    let body_start = skip_ascii_whitespace(bytes, as_end);
    if body_start >= bytes.len() {
        return None;
    }
    if match_ascii_keyword_at(bytes, body_start, b"BEGIN").is_some() {
        return None;
    }

    let mut tail = bytes.len();
    while tail > 0 && is_ascii_whitespace_byte(bytes[tail - 1]) {
        tail -= 1;
    }
    if tail <= body_start {
        return None;
    }

    let final_semicolon = if bytes[tail - 1] == b';' {
        Some(tail - 1)
    } else {
        None
    };

    Some((body_start, tail, final_semicolon))
}

fn is_ascii_whitespace_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn is_ascii_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ascii_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && is_ascii_whitespace_byte(bytes[index]) {
        index += 1;
    }
    index
}

fn consume_ascii_identifier(bytes: &[u8], start: usize) -> Option<usize> {
    if start >= bytes.len() || !is_ascii_ident_start(bytes[start]) {
        return None;
    }
    let mut index = start + 1;
    while index < bytes.len() && is_ascii_ident_continue(bytes[index]) {
        index += 1;
    }
    Some(index)
}

fn is_word_boundary_for_keyword(bytes: &[u8], index: usize) -> bool {
    index == 0 || index >= bytes.len() || !is_ascii_ident_continue(bytes[index])
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

fn procedure_body_uses_begin_end(body: &ConditionalStatements) -> bool {
    matches!(body, ConditionalStatements::BeginEnd(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_sql;
    use crate::types::IssueAutofixApplicability;

    fn run(sql: &str) -> Vec<Issue> {
        let statements = parse_sql(sql).expect("parse");
        let rule = TsqlProcedureBeginEnd;
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
    fn flags_procedure_without_begin_end() {
        let sql = "CREATE PROCEDURE p AS SELECT 1;";
        let issues = run(sql);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, issue_codes::LINT_TQ_002);
        let autofix = issues[0].autofix.as_ref().expect("autofix metadata");
        assert_eq!(autofix.applicability, IssueAutofixApplicability::Safe);
        let fixed = apply_issue_autofix(sql, &issues[0]).expect("apply autofix");
        assert_eq!(fixed, "CREATE PROCEDURE p AS BEGIN SELECT 1; END;");
    }

    #[test]
    fn does_not_flag_procedure_with_begin_end() {
        let issues = run("CREATE PROCEDURE p AS BEGIN SELECT 1; END;");
        assert!(issues.is_empty());
    }

    #[test]
    fn does_not_flag_procedure_text_inside_string_literal() {
        let issues = run("SELECT 'CREATE PROCEDURE p AS SELECT 1' AS sql_snippet");
        assert!(issues.is_empty());
    }
}
