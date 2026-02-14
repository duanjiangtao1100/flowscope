//! Common types shared between request and response.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Case sensitivity for identifier normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum CaseSensitivity {
    /// Use dialect default
    #[default]
    Dialect,
    /// Lowercase normalization (Postgres)
    Lower,
    /// Uppercase normalization (Snowflake)
    Upper,
    /// Case-sensitive as-is (BigQuery)
    Exact,
}

impl CaseSensitivity {
    /// Resolves this case sensitivity setting to a concrete normalization strategy.
    ///
    /// When `self` is `Dialect`, uses the dialect's default strategy.
    /// Otherwise, returns the explicit strategy requested.
    pub fn resolve(&self, dialect: crate::Dialect) -> crate::generated::NormalizationStrategy {
        use crate::generated::NormalizationStrategy;
        match self {
            Self::Dialect => dialect.normalization_strategy(),
            Self::Lower => NormalizationStrategy::Lowercase,
            Self::Upper => NormalizationStrategy::Uppercase,
            Self::Exact => NormalizationStrategy::CaseSensitive,
        }
    }
}

/// Lint execution engine category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LintEngine {
    Semantic,
    Lexical,
    Document,
}

/// Confidence level attached to lint findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LintConfidence {
    High,
    Medium,
    Low,
}

/// Source of degraded lint confidence or fallback behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LintFallbackSource {
    ParserFallback,
    TokenizerFallback,
    HeuristicRule,
}

/// Autofix applicability metadata for an issue.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum IssueAutofixApplicability {
    /// The fix is considered safe and should not change semantics.
    Safe,
    /// The fix may change semantics and should require explicit opt-in.
    Unsafe,
    /// The fix is presented for visibility only and should not be auto-applied.
    DisplayOnly,
}

/// A text patch edit associated with an issue autofix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuePatchEdit {
    /// Byte range in the source SQL to replace.
    pub span: Span,
    /// Replacement text for the target span.
    pub replacement: String,
}

impl IssuePatchEdit {
    pub fn new(span: Span, replacement: impl Into<String>) -> Self {
        Self {
            span,
            replacement: replacement.into(),
        }
    }
}

/// Autofix metadata attached to an issue.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssueAutofix {
    /// Applicability category for this fix.
    pub applicability: IssueAutofixApplicability,
    /// Edits required to apply this fix.
    pub edits: Vec<IssuePatchEdit>,
}

impl IssueAutofix {
    pub fn new(applicability: IssueAutofixApplicability, edits: Vec<IssuePatchEdit>) -> Self {
        Self {
            applicability,
            edits,
        }
    }
}

/// An issue encountered during SQL analysis (error, warning, or info).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Issue {
    /// Severity level
    pub severity: Severity,

    /// Machine-readable issue code
    pub code: String,

    /// Human-readable error message
    pub message: String,

    /// SQLFluff dotted rule name (e.g., `aliasing.table`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sqlfluff_name: Option<String>,

    /// Optional: location in source SQL where issue occurred
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,

    /// Optional: which statement index this issue relates to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_index: Option<usize>,

    /// Optional: source file name where the issue occurred
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,

    /// Optional: linter engine provenance (`semantic`, `lexical`, `document`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint_engine: Option<LintEngine>,

    /// Optional: confidence level for lint detection quality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint_confidence: Option<LintConfidence>,

    /// Optional: fallback mode used while evaluating this lint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint_fallback_source: Option<LintFallbackSource>,

    /// Optional: autofix metadata for this issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofix: Option<IssueAutofix>,
}

impl Issue {
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: code.into(),
            message: message.into(),
            sqlfluff_name: None,
            span: None,
            statement_index: None,
            source_name: None,
            lint_engine: None,
            lint_confidence: None,
            lint_fallback_source: None,
            autofix: None,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: code.into(),
            message: message.into(),
            sqlfluff_name: None,
            span: None,
            statement_index: None,
            source_name: None,
            lint_engine: None,
            lint_confidence: None,
            lint_fallback_source: None,
            autofix: None,
        }
    }

    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            code: code.into(),
            message: message.into(),
            sqlfluff_name: None,
            span: None,
            statement_index: None,
            source_name: None,
            lint_engine: None,
            lint_confidence: None,
            lint_fallback_source: None,
            autofix: None,
        }
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    pub fn with_statement(mut self, index: usize) -> Self {
        self.statement_index = Some(index);
        self
    }

    pub fn with_source_name(mut self, name: impl Into<String>) -> Self {
        self.source_name = Some(name.into());
        self
    }

    pub fn with_lint_engine(mut self, engine: LintEngine) -> Self {
        self.lint_engine = Some(engine);
        self
    }

    pub fn with_lint_confidence(mut self, confidence: LintConfidence) -> Self {
        self.lint_confidence = Some(confidence);
        self
    }

    pub fn with_lint_fallback_source(mut self, source: LintFallbackSource) -> Self {
        self.lint_fallback_source = Some(source);
        self
    }

    /// Attach autofix metadata.
    pub fn with_autofix(mut self, autofix: IssueAutofix) -> Self {
        self.autofix = Some(autofix);
        self
    }

    /// Attach autofix metadata from applicability and edit list.
    pub fn with_autofix_edits(
        mut self,
        applicability: IssueAutofixApplicability,
        edits: Vec<IssuePatchEdit>,
    ) -> Self {
        self.autofix = Some(IssueAutofix::new(applicability, edits));
        self
    }

    /// Attach a SQLFluff dotted rule name.
    pub fn with_sqlfluff_name(mut self, name: impl Into<String>) -> Self {
        self.sqlfluff_name = Some(name.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A byte range in the source SQL string.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct Span {
    /// Byte offset from start of SQL string (inclusive)
    pub start: usize,
    /// Byte offset from start of SQL string (exclusive)
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// Summary statistics for the analysis result.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    /// Total number of statements analyzed
    pub statement_count: usize,

    /// Total unique tables/CTEs discovered across all statements
    pub table_count: usize,

    /// Total columns in output (Phase 2+)
    pub column_count: usize,

    /// Total number of JOIN operations
    pub join_count: usize,

    /// Complexity score (1-100) based on query structure
    pub complexity_score: u8,

    /// Issue counts by severity
    pub issue_count: IssueCount,

    /// Quick check: true if any errors were encountered
    pub has_errors: bool,
}

/// Counts of issues by severity level.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct IssueCount {
    /// Number of error-level issues
    pub errors: usize,
    /// Number of warning-level issues
    pub warnings: usize,
    /// Number of info-level issues
    pub infos: usize,
}

/// Machine-readable issue codes.
pub mod issue_codes {
    pub const PARSE_ERROR: &str = "PARSE_ERROR";
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const DIALECT_FALLBACK: &str = "DIALECT_FALLBACK";
    pub const UNSUPPORTED_SYNTAX: &str = "UNSUPPORTED_SYNTAX";
    pub const UNSUPPORTED_RECURSIVE_CTE: &str = "UNSUPPORTED_RECURSIVE_CTE";
    pub const APPROXIMATE_LINEAGE: &str = "APPROXIMATE_LINEAGE";
    pub const UNKNOWN_COLUMN: &str = "UNKNOWN_COLUMN";
    pub const UNKNOWN_TABLE: &str = "UNKNOWN_TABLE";
    pub const UNRESOLVED_REFERENCE: &str = "UNRESOLVED_REFERENCE";
    pub const CANCELLED: &str = "CANCELLED";
    pub const PAYLOAD_SIZE_WARNING: &str = "PAYLOAD_SIZE_WARNING";
    pub const MEMORY_LIMIT_EXCEEDED: &str = "MEMORY_LIMIT_EXCEEDED";
    pub const SCHEMA_CONFLICT: &str = "SCHEMA_CONFLICT";
    pub const TEMPLATE_ERROR: &str = "TEMPLATE_ERROR";
    pub const TYPE_MISMATCH: &str = "TYPE_MISMATCH";

    // Lint rules — ambiguity
    pub const LINT_AM_001: &str = "LINT_AM_001";
    pub const LINT_AM_002: &str = "LINT_AM_002";
    pub const LINT_AM_003: &str = "LINT_AM_003";
    pub const LINT_AM_004: &str = "LINT_AM_004";
    pub const LINT_AM_005: &str = "LINT_AM_005";
    pub const LINT_AM_006: &str = "LINT_AM_006";
    pub const LINT_AM_007: &str = "LINT_AM_007";
    pub const LINT_AM_008: &str = "LINT_AM_008";
    pub const LINT_AM_009: &str = "LINT_AM_009";

    // Lint rules — capitalisation
    pub const LINT_CP_001: &str = "LINT_CP_001";
    pub const LINT_CP_002: &str = "LINT_CP_002";
    pub const LINT_CP_003: &str = "LINT_CP_003";
    pub const LINT_CP_004: &str = "LINT_CP_004";
    pub const LINT_CP_005: &str = "LINT_CP_005";

    // Lint rules — convention
    pub const LINT_CV_001: &str = "LINT_CV_001";
    pub const LINT_CV_002: &str = "LINT_CV_002";
    pub const LINT_CV_003: &str = "LINT_CV_003";
    pub const LINT_CV_004: &str = "LINT_CV_004";
    pub const LINT_CV_005: &str = "LINT_CV_005";
    pub const LINT_CV_006: &str = "LINT_CV_006";
    pub const LINT_CV_007: &str = "LINT_CV_007";
    pub const LINT_CV_008: &str = "LINT_CV_008";
    pub const LINT_CV_009: &str = "LINT_CV_009";
    pub const LINT_CV_010: &str = "LINT_CV_010";
    pub const LINT_CV_011: &str = "LINT_CV_011";
    pub const LINT_CV_012: &str = "LINT_CV_012";

    // Lint rules — jinja
    pub const LINT_JJ_001: &str = "LINT_JJ_001";

    // Lint rules — layout
    pub const LINT_LT_001: &str = "LINT_LT_001";
    pub const LINT_LT_002: &str = "LINT_LT_002";
    pub const LINT_LT_003: &str = "LINT_LT_003";
    pub const LINT_LT_004: &str = "LINT_LT_004";
    pub const LINT_LT_005: &str = "LINT_LT_005";
    pub const LINT_LT_006: &str = "LINT_LT_006";
    pub const LINT_LT_007: &str = "LINT_LT_007";
    pub const LINT_LT_008: &str = "LINT_LT_008";
    pub const LINT_LT_009: &str = "LINT_LT_009";
    pub const LINT_LT_010: &str = "LINT_LT_010";
    pub const LINT_LT_011: &str = "LINT_LT_011";
    pub const LINT_LT_012: &str = "LINT_LT_012";
    pub const LINT_LT_013: &str = "LINT_LT_013";
    pub const LINT_LT_014: &str = "LINT_LT_014";
    pub const LINT_LT_015: &str = "LINT_LT_015";

    // Lint rules — references
    pub const LINT_RF_001: &str = "LINT_RF_001";
    pub const LINT_RF_002: &str = "LINT_RF_002";
    pub const LINT_RF_003: &str = "LINT_RF_003";
    pub const LINT_RF_004: &str = "LINT_RF_004";
    pub const LINT_RF_005: &str = "LINT_RF_005";
    pub const LINT_RF_006: &str = "LINT_RF_006";

    // Lint rules — structure
    pub const LINT_ST_001: &str = "LINT_ST_001";
    pub const LINT_ST_002: &str = "LINT_ST_002";
    pub const LINT_ST_003: &str = "LINT_ST_003";
    pub const LINT_ST_004: &str = "LINT_ST_004";
    pub const LINT_ST_005: &str = "LINT_ST_005";
    pub const LINT_ST_006: &str = "LINT_ST_006";
    pub const LINT_ST_007: &str = "LINT_ST_007";
    pub const LINT_ST_008: &str = "LINT_ST_008";
    pub const LINT_ST_009: &str = "LINT_ST_009";
    pub const LINT_ST_010: &str = "LINT_ST_010";
    pub const LINT_ST_011: &str = "LINT_ST_011";
    pub const LINT_ST_012: &str = "LINT_ST_012";

    // Lint rules — aliasing
    pub const LINT_AL_001: &str = "LINT_AL_001";
    pub const LINT_AL_002: &str = "LINT_AL_002";
    pub const LINT_AL_003: &str = "LINT_AL_003";
    pub const LINT_AL_004: &str = "LINT_AL_004";
    pub const LINT_AL_005: &str = "LINT_AL_005";
    pub const LINT_AL_006: &str = "LINT_AL_006";
    pub const LINT_AL_007: &str = "LINT_AL_007";
    pub const LINT_AL_008: &str = "LINT_AL_008";
    pub const LINT_AL_009: &str = "LINT_AL_009";

    // Lint rules — tsql
    pub const LINT_TQ_001: &str = "LINT_TQ_001";
    pub const LINT_TQ_002: &str = "LINT_TQ_002";
    pub const LINT_TQ_003: &str = "LINT_TQ_003";
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;
    use serde_json::json;

    #[test]
    fn test_issue_creation() {
        let issue = Issue::error("PARSE_ERROR", "Unexpected token")
            .with_span(Span::new(10, 20))
            .with_statement(0)
            .with_lint_engine(LintEngine::Semantic)
            .with_lint_confidence(LintConfidence::High)
            .with_autofix_edits(
                IssueAutofixApplicability::Safe,
                vec![IssuePatchEdit::new(Span::new(10, 20), "SELECT")],
            );

        assert_eq!(issue.severity, Severity::Error);
        assert_eq!(issue.code, "PARSE_ERROR");
        assert_eq!(issue.span.unwrap().start, 10);
        assert_eq!(issue.statement_index, Some(0));
        assert_eq!(issue.lint_engine, Some(LintEngine::Semantic));
        assert_eq!(
            issue.autofix.as_ref().map(|fix| fix.applicability),
            Some(IssueAutofixApplicability::Safe)
        );
    }

    #[test]
    fn test_issue_autofix_serde_and_schema() {
        let issue = Issue::warning("LINT_X", "needs fix").with_autofix(IssueAutofix::new(
            IssueAutofixApplicability::DisplayOnly,
            vec![IssuePatchEdit::new(Span::new(2, 4), "ab")],
        ));

        let value = serde_json::to_value(&issue).expect("serialize issue");
        assert_eq!(value["autofix"]["applicability"], json!("displayOnly"));
        assert_eq!(value["autofix"]["edits"][0]["span"]["start"], json!(2));
        assert_eq!(value["autofix"]["edits"][0]["replacement"], json!("ab"));

        let roundtrip: Issue = serde_json::from_value(value).expect("deserialize issue");
        assert_eq!(
            roundtrip.autofix.as_ref().map(|fix| fix.applicability),
            Some(IssueAutofixApplicability::DisplayOnly)
        );

        let schema = schema_for!(Issue);
        let schema_json = serde_json::to_value(schema).expect("serialize issue schema");
        let schema_text = schema_json.to_string();
        assert!(schema_text.contains("\"autofix\""));
        assert!(schema_text.contains("\"replacement\""));
        assert!(schema_text.contains("\"safe\""));
        assert!(schema_text.contains("\"unsafe\""));
        assert!(schema_text.contains("\"displayOnly\""));
    }
}
