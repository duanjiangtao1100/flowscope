//! Unit tests for serve mode API handlers.
//!
//! These tests verify the API endpoints work correctly with mock state,
//! without starting a full HTTP server.

#![cfg(feature = "serve")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use flowscope_cli::server::{build_router, state::AppState, state::ServerConfig};
use flowscope_core::{Dialect, FileSource};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tower::ServiceExt;

/// Create a test AppState without loading files from disk.
fn test_state(config: ServerConfig, files: Vec<FileSource>) -> Arc<AppState> {
    Arc::new(AppState {
        config,
        files: RwLock::new(files),
        schema: RwLock::new(None),
        mtimes: RwLock::new(HashMap::new()),
    })
}

fn default_config() -> ServerConfig {
    ServerConfig {
        dialect: Dialect::Generic,
        watch_dirs: vec![],
        static_files: None,
        metadata_url: None,
        metadata_schema: None,
        port: 3000,
        open_browser: false,
        schema_path: None,
        #[cfg(feature = "templating")]
        template_config: None,
    }
}

async fn post_json(app: &Router, path: &str, payload: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

// === Health endpoint tests ===

#[tokio::test]
async fn health_returns_ok_status() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
}

// === Analyze endpoint tests ===

#[tokio::test]
async fn analyze_simple_select() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/analyze")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT id, name FROM users"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Check that analysis result has expected structure
    assert!(json["statements"].is_array());
}

#[tokio::test]
async fn analyze_with_join() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/analyze")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Verify we got statements back
    assert!(json["statements"].is_array());
    assert!(!json["statements"].as_array().unwrap().is_empty());
}

// === Completion endpoint tests ===

#[tokio::test]
async fn completion_returns_items() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/completion")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT ",
                        "cursor_offset": 7
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Completion response should have items array
    assert!(json["items"].is_array());
}

// === Split endpoint tests ===

#[tokio::test]
async fn split_multiple_statements() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/split")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT 1; SELECT 2; SELECT 3"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Should have statements array
    assert!(json["statements"].is_array());
    assert_eq!(json["statements"].as_array().unwrap().len(), 3);
}

// === Lint fix endpoint tests ===

#[tokio::test]
async fn lint_fix_applies_safe_fix_and_reports_counts() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT COUNT (1) FROM t"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(json["skipped_due_to_regression"], false);
    assert!(json["fix_counts"]["total"].as_u64().unwrap() > 0);

    let fixed_sql = json["sql"].as_str().unwrap().to_ascii_uppercase();
    assert!(
        fixed_sql.contains("COUNT(*)") || fixed_sql.contains("COUNT (*)"),
        "fixed SQL was: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_rule_config_enables_cv006_core_autofix() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT 1",
            "rule_configs": {
                "convention.terminator": {
                    "require_final_semicolon": true
                }
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        fixed_sql.trim_end().ends_with(';'),
        "expected CV06 core autofix to append final semicolon: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_applies_cv006_spacing_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT a FROM foo  ;"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(
        json["sql"].as_str().unwrap(),
        "SELECT a FROM foo;",
        "expected CV06 core autofix to remove whitespace before semicolon"
    );
}

#[tokio::test]
async fn lint_fix_applies_cv002_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT IFNULL(foo, 0) FROM t"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap().to_ascii_uppercase();
    assert!(
        fixed_sql.contains("COALESCE"),
        "expected CV02 core autofix to rewrite IFNULL: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_applies_cv001_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT * FROM t WHERE a <> b AND c != d"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        !fixed_sql.contains("<>"),
        "expected CV01 core autofix to normalize not-equal style: {fixed_sql}"
    );
    assert!(
        fixed_sql.contains("!="),
        "expected CV01 core autofix to keep C-style not-equal operator: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_applies_cv005_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT * FROM t WHERE a = NULL AND b <> NULL"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        fixed_sql.contains("a IS NULL"),
        "expected CV05 core autofix to rewrite '= NULL': {fixed_sql}"
    );
    assert!(
        fixed_sql.contains("b IS NOT NULL"),
        "expected CV05 core autofix to rewrite '<> NULL': {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_applies_cv007_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "(SELECT 1)"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(
        json["sql"].as_str().unwrap(),
        "SELECT 1",
        "expected CV07 core autofix to remove outer wrapper brackets"
    );
}

#[tokio::test]
async fn lint_fix_applies_lt006_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT COUNT (1) FROM t"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        fixed_sql.contains("COUNT("),
        "expected LT06 core autofix to keep function call parenthesis tight: {fixed_sql}"
    );
    assert!(
        !fixed_sql.contains("COUNT ("),
        "expected LT06 core autofix to remove spacing before function parenthesis: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_applies_cv003_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT a, FROM t"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(
        json["sql"].as_str().unwrap(),
        "SELECT a FROM t",
        "expected CV003 core autofix to remove trailing comma"
    );
}

#[tokio::test]
async fn lint_fix_rule_config_enables_cv003_require_core_autofix() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT a FROM t",
            "rule_configs": {
                "convention.select_trailing_comma": {
                    "select_clause_trailing_comma": "require"
                }
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(
        json["sql"].as_str().unwrap(),
        "SELECT a, FROM t",
        "expected CV003 require-mode core autofix to insert trailing comma"
    );
}

#[tokio::test]
async fn lint_fix_applies_st012_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT 1;;"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(
        json["sql"].as_str().unwrap(),
        "SELECT 1;",
        "expected ST012 core autofix to collapse consecutive semicolons"
    );
}

#[tokio::test]
async fn lint_fix_applies_lt012_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT 1\nFROM t"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    assert_eq!(
        json["sql"].as_str().unwrap(),
        "SELECT 1\nFROM t\n",
        "expected LT012 core autofix to enforce exactly one trailing newline"
    );
}

#[tokio::test]
async fn lint_fix_applies_lt013_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "\n\nSELECT 1"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        fixed_sql.starts_with("SELECT 1"),
        "expected LT013 core autofix to remove leading blank lines: {fixed_sql:?}"
    );
    assert!(
        !fixed_sql.starts_with('\n'),
        "expected LT013 output to start with SQL text: {fixed_sql:?}"
    );
}

#[tokio::test]
async fn lint_fix_applies_lt014_core_autofix_in_patch_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT a FROM t\nWHERE a = 1"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["changed"], true);
    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        fixed_sql.contains("\nFROM t"),
        "expected LT014 core autofix to line-break major clause keyword: {fixed_sql:?}"
    );
}

#[tokio::test]
async fn lint_fix_applies_jj001_core_autofix_only_in_unsafe_mode() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);
    let sql = "SELECT '{{foo}}' AS templated";

    let (safe_status, safe_json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": sql,
            "unsafe_fixes": false
        }),
    )
    .await;
    let (unsafe_status, unsafe_json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": sql,
            "unsafe_fixes": true
        }),
    )
    .await;

    assert_eq!(safe_status, StatusCode::OK);
    assert_eq!(unsafe_status, StatusCode::OK);
    assert_eq!(
        safe_json["sql"].as_str().unwrap(),
        sql,
        "safe mode should keep JJ001 template edits blocked by protected ranges"
    );
    assert!(
        unsafe_json["sql"].as_str().unwrap().contains("{{ foo }}"),
        "unsafe mode should apply JJ001 core autofix: {}",
        unsafe_json["sql"].as_str().unwrap()
    );
}

#[tokio::test]
async fn lint_fix_safe_vs_unsafe_mode_shows_expected_delta() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);
    let sql = "SELECT * FROM (SELECT 1) sub";

    let (safe_status, safe_json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": sql,
            "unsafe_fixes": false,
            "legacy_ast_fixes": true
        }),
    )
    .await;
    let (unsafe_status, unsafe_json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": sql,
            "unsafe_fixes": true,
            "legacy_ast_fixes": true
        }),
    )
    .await;

    assert_eq!(safe_status, StatusCode::OK);
    assert_eq!(unsafe_status, StatusCode::OK);

    let safe_sql = safe_json["sql"].as_str().unwrap().to_ascii_uppercase();
    let unsafe_sql = unsafe_json["sql"].as_str().unwrap().to_ascii_uppercase();

    assert!(
        !safe_sql.contains("WITH SUB AS"),
        "safe mode should not apply ST_005 rewrite: {safe_sql}"
    );
    assert!(
        unsafe_sql.contains("WITH SUB AS"),
        "unsafe mode with legacy AST rewrites should apply ST_005 rewrite: {unsafe_sql}"
    );
    assert!(
        safe_json["skipped_counts"]["unsafe_skipped"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(unsafe_json["skipped_counts"]["unsafe_skipped"], 0);
}

#[tokio::test]
async fn lint_fix_unsafe_without_legacy_ast_rewrites_keeps_st05_shape() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);
    let sql = "SELECT * FROM (SELECT 1) sub";

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": sql,
            "unsafe_fixes": true
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let fixed_sql = json["sql"].as_str().unwrap().to_ascii_uppercase();
    assert!(
        !fixed_sql.contains("WITH SUB AS"),
        "unsafe patch mode without legacy AST rewrites should not emit ST_005 CTE rewrite: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_preserves_comments_while_fixing_non_comment_regions() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "-- keep this comment\nSELECT COUNT (1) FROM t"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["skipped_due_to_comments"], false);

    let fixed_sql = json["sql"].as_str().unwrap();
    assert!(
        fixed_sql.contains("-- keep this comment"),
        "comment must be preserved: {fixed_sql}"
    );
    assert!(
        fixed_sql.to_ascii_uppercase().contains("COUNT (*)")
            || fixed_sql.to_ascii_uppercase().contains("COUNT(*)"),
        "non-comment fix should still apply: {fixed_sql}"
    );
}

#[tokio::test]
async fn lint_fix_respects_disabled_rules() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let (status, json) = post_json(
        &app,
        "/api/lint-fix",
        json!({
            "sql": "SELECT * FROM (SELECT 1) sub",
            "unsafe_fixes": true,
            "legacy_ast_fixes": true,
            "disabled_rules": ["LINT_ST_005"]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!json["sql"]
        .as_str()
        .unwrap()
        .to_ascii_uppercase()
        .contains("WITH SUB AS"));
    assert_eq!(json["skipped_counts"]["unsafe_skipped"], 0);
}

#[tokio::test]
async fn lint_fix_rejects_non_object_rule_config_entries() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/lint-fix")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT 1",
                        "rule_configs": {
                            "structure.subquery": "both"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let message = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        message.contains("'rule_configs' entry for 'structure.subquery' must be a JSON object"),
        "unexpected error message: {message}"
    );
}

// === Files endpoint tests ===

#[tokio::test]
async fn files_returns_empty_when_no_files() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(Request::get("/api/files").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn files_returns_loaded_files() {
    let files = vec![
        FileSource {
            name: "queries.sql".to_string(),
            content: "SELECT * FROM users".to_string(),
        },
        FileSource {
            name: "reports/summary.sql".to_string(),
            content: "SELECT COUNT(*) FROM orders".to_string(),
        },
    ];

    let state = test_state(default_config(), files);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(Request::get("/api/files").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array());
    assert_eq!(json.as_array().unwrap().len(), 2);

    let first = &json[0];
    assert_eq!(first["name"], "queries.sql");
    assert_eq!(first["content"], "SELECT * FROM users");
}

// === Schema endpoint tests ===

#[tokio::test]
async fn schema_returns_null_when_no_schema() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(Request::get("/api/schema").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_null());
}

// === Config endpoint tests ===

#[tokio::test]
async fn config_returns_server_configuration() {
    let config = ServerConfig {
        dialect: Dialect::Postgres,
        watch_dirs: vec![PathBuf::from("/tmp/sql")],
        static_files: None,
        metadata_url: None,
        metadata_schema: None,
        port: 8080,
        open_browser: false,
        schema_path: None,
        #[cfg(feature = "templating")]
        template_config: None,
    };

    let state = test_state(config, vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(Request::get("/api/config").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["dialect"], "Postgres");
    assert!(json["watch_dirs"].is_array());
    assert_eq!(json["has_schema"], false);
}

// === Export endpoint tests ===

#[tokio::test]
async fn export_json_format() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/export/json")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT id FROM users"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn export_mermaid_format() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/export/mermaid")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT id FROM users"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain"
    );
}

#[tokio::test]
async fn export_unknown_format_returns_error() {
    let state = test_state(default_config(), vec![]);
    let app = build_router(state, 3000);

    let response = app
        .oneshot(
            Request::post("/api/export/unknown")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "sql": "SELECT id FROM users"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
