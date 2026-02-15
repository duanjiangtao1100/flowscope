#!/usr/bin/env python3
"""Compare FlowScope lint/fix results against SQLFluff YAML test fixtures.

Usage:
    python scripts/sqlfluff-parity-report.py [SQLFLUFF_DIR]

    SQLFLUFF_DIR  Path to a SQLFluff source checkout with a .venv containing
                  sqlfluff installed.  Defaults to the SQLFLUFF_DIR environment
                  variable or ../tries/2026-01-20-sqlfluff relative to this repo.

The script:
  1. Builds FlowScope CLI in release mode (cargo build -p flowscope-cli --release)
  2. Iterates through every SQLFluff YAML fixture in
     SQLFLUFF_DIR/test/fixtures/rules/std_rule_cases/*.yml
  3. For each test case:
     - pass_str: verifies FlowScope does NOT report the target rule
     - fail_str: verifies FlowScope DOES report the target rule
     - fix_str:  compares FlowScope --fix output against the expected fix
  4. Prints a human-readable parity report to stdout

Requirements:
  - Python 3.10+
  - PyYAML (pip install pyyaml) — or use the SQLFluff venv which includes it
  - Rust toolchain (for cargo build)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "PyYAML is required.  Install it or run this script with the SQLFluff venv:\n"
        "  /path/to/sqlfluff/.venv/bin/python scripts/sqlfluff-parity-report.py",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
FLOWSCOPE_BIN = REPO_ROOT / "target" / "release" / "flowscope"

# Map SQLFluff dialect names → FlowScope dialect names.
# None means "not supported by FlowScope — skip".
DIALECT_MAP: dict[str, str | None] = {
    "ansi": "ansi",
    "bigquery": "bigquery",
    "clickhouse": "clickhouse",
    "databricks": "databricks",
    "duckdb": "duckdb",
    "hive": "hive",
    "mysql": "mysql",
    "postgres": "postgres",
    "redshift": "redshift",
    "snowflake": "snowflake",
    "sparksql": "sparksql",
    "sqlite": "sqlite",
    "tsql": "mssql",
    # Unsupported dialects
    "athena": None,
    "db2": None,
    "exasol": None,
    "greenplum": None,
    "mariadb": None,
    "materialize": None,
    "oracle": None,
    "soql": None,
    "teradata": None,
    "trino": None,
    "vertica": None,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def resolve_sqlfluff_dir() -> Path:
    """Resolve the SQLFluff source directory from args / env / default."""
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).resolve()
    if env := os.environ.get("SQLFLUFF_DIR"):
        return Path(env).resolve()
    # Default: sibling directory convention
    default = REPO_ROOT.parent.parent / "tries" / "2026-01-20-sqlfluff"
    if default.is_dir():
        return default
    print(
        "Cannot find SQLFluff directory.  Pass it as an argument:\n"
        "  python scripts/sqlfluff-parity-report.py /path/to/sqlfluff",
        file=sys.stderr,
    )
    sys.exit(1)


def build_flowscope() -> None:
    """Build FlowScope CLI in release mode."""
    print("Building FlowScope CLI (release)…", flush=True)
    result = subprocess.run(
        ["cargo", "build", "-p", "flowscope-cli", "--release"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    print("Build complete.\n", flush=True)


def extract_rule_configs(configs: dict | None) -> dict | None:
    """Extract rules: section from SQLFluff fixture configs as a flat dict.

    SQLFluff fixtures use:
        configs:
          rules:
            references.special_chars:
              quoted_identifiers_policy: aliases

    We flatten this to: {"references.special_chars": {"quoted_identifiers_policy": "aliases"}}
    which maps directly to the --rule-configs JSON format.
    """
    if not configs:
        return None
    rules = configs.get("rules")
    if not rules or not isinstance(rules, dict):
        return None
    # Return rules dict as-is; keys are dotted rule names, values are option dicts.
    return {k: v for k, v in rules.items() if isinstance(v, dict)}


def _build_flowscope_cmd(
    base_args: list[str],
    dialect: str,
    filepath: str,
    rule_configs: dict | None = None,
) -> list[str]:
    """Build the flowscope CLI command with optional --rule-configs."""
    cmd = [str(FLOWSCOPE_BIN)] + base_args + [filepath, "--dialect", dialect]
    if rule_configs:
        cmd.extend(["--rule-configs", json.dumps(rule_configs)])
    return cmd


def run_flowscope_lint(
    sql: str,
    dialect: str = "generic",
    rule: str | None = None,
    rule_configs: dict | None = None,
) -> list[dict]:
    """Run FlowScope lint and return violations for the target rule."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sql", delete=False
    ) as f:
        f.write(sql)
        f.flush()
        try:
            cmd = _build_flowscope_cmd(
                ["--lint", "--format", "json"], dialect, f.name, rule_configs
            )
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode not in (0, 1):
                return []
            try:
                data = json.loads(result.stdout)
                violations = data[0].get("violations", []) if data else []
                if rule:
                    violations = [v for v in violations if v.get("code") == rule]
                return violations
            except (json.JSONDecodeError, IndexError, KeyError):
                return []
        except subprocess.TimeoutExpired:
            return []
        finally:
            os.unlink(f.name)


def run_flowscope_fix(
    sql: str,
    dialect: str = "generic",
    rule_configs: dict | None = None,
) -> str | None:
    """Run FlowScope --fix and return the fixed SQL."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sql", delete=False
    ) as f:
        f.write(sql)
        f.flush()
        try:
            cmd = _build_flowscope_cmd(
                ["--lint", "--fix", "--format", "json"],
                dialect,
                f.name,
                rule_configs,
            )
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode not in (0, 1):
                return None
            with open(f.name) as fixed:
                return fixed.read()
        except subprocess.TimeoutExpired:
            return None
        finally:
            os.unlink(f.name)


def normalize_whitespace(s: str) -> str:
    """Collapse whitespace for loose fix comparison."""
    return " ".join(s.split())


def get_dialect(configs: dict | None) -> str:
    """Extract dialect from SQLFluff fixture configs."""
    if not configs:
        return "ansi"
    core = configs.get("core", {})
    return core.get("dialect", "ansi")


def parse_fixture(path: Path) -> tuple[str, list[dict]]:
    """Parse a SQLFluff YAML fixture into (rule_code, cases)."""
    with open(path) as f:
        data = yaml.safe_load(f)

    rule_code = data.get("rule", "")
    cases: list[dict] = []

    for key, value in data.items():
        if key == "rule" or not isinstance(value, dict):
            continue
        case: dict = {
            "name": key,
            "configs": value.get("configs"),
        }
        if "pass_str" in value:
            case["type"] = "pass"
            case["sql"] = value["pass_str"]
        elif "fail_str" in value:
            case["type"] = "fail"
            case["sql"] = value["fail_str"]
            if "fix_str" in value:
                case["fix_str"] = value["fix_str"]
        else:
            continue
        cases.append(case)

    return rule_code, cases


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    sqlfluff_dir = resolve_sqlfluff_dir()
    fixtures_dir = sqlfluff_dir / "test" / "fixtures" / "rules" / "std_rule_cases"
    if not fixtures_dir.is_dir():
        print(f"Fixtures directory not found: {fixtures_dir}", file=sys.stderr)
        sys.exit(1)

    build_flowscope()

    fixture_files = sorted(fixtures_dir.glob("*.yml"))
    print(f"Found {len(fixture_files)} fixture files\n")

    # Aggregate counters.
    total_cases = 0
    total_pass_agree = 0
    total_pass_disagree = 0
    total_fail_agree = 0
    total_fail_disagree = 0
    total_fix_match = 0
    total_fix_mismatch = 0
    total_fix_cases = 0
    total_skipped_dialect = 0

    rule_results: dict[str, dict] = {}
    fix_mismatches: list[dict] = []
    detection_disagreements: list[dict] = []

    start_time = time.time()

    for fixture_path in fixture_files:
        if fixture_path.name == "README.md":
            continue

        rule_code, cases = parse_fixture(fixture_path)
        if not rule_code or not cases:
            continue

        r_pass_ok = 0
        r_pass_bad = 0
        r_fail_ok = 0
        r_fail_bad = 0
        r_fix_ok = 0
        r_fix_bad = 0
        r_fix_total = 0
        r_skip = 0

        for case in cases:
            sql = case.get("sql", "")
            if not sql or not sql.strip():
                continue

            sqlfluff_dialect = get_dialect(case.get("configs"))
            fs_dialect = DIALECT_MAP.get(sqlfluff_dialect)
            if fs_dialect is None:
                r_skip += 1
                total_skipped_dialect += 1
                continue

            total_cases += 1

            case_rule_configs = extract_rule_configs(case.get("configs"))
            fs_violations = run_flowscope_lint(
                sql, fs_dialect, rule_code, case_rule_configs
            )
            fs_has = len(fs_violations) > 0

            if case["type"] == "pass":
                if not fs_has:
                    r_pass_ok += 1
                    total_pass_agree += 1
                else:
                    r_pass_bad += 1
                    total_pass_disagree += 1
                    detection_disagreements.append(
                        {
                            "file": fixture_path.name,
                            "case": case["name"],
                            "rule": rule_code,
                            "type": "false_positive",
                            "dialect": sqlfluff_dialect,
                            "sql": sql.strip()[:120],
                            "fs_codes": [v.get("code") for v in fs_violations],
                        }
                    )
            elif case["type"] == "fail":
                if fs_has:
                    r_fail_ok += 1
                    total_fail_agree += 1
                else:
                    r_fail_bad += 1
                    total_fail_disagree += 1
                    detection_disagreements.append(
                        {
                            "file": fixture_path.name,
                            "case": case["name"],
                            "rule": rule_code,
                            "type": "false_negative",
                            "dialect": sqlfluff_dialect,
                            "sql": sql.strip()[:120],
                        }
                    )

                if "fix_str" in case:
                    r_fix_total += 1
                    total_fix_cases += 1
                    fs_fixed = run_flowscope_fix(sql, fs_dialect, case_rule_configs)
                    expected = case["fix_str"]

                    if fs_fixed is not None and normalize_whitespace(
                        fs_fixed
                    ) == normalize_whitespace(expected):
                        r_fix_ok += 1
                        total_fix_match += 1
                    else:
                        r_fix_bad += 1
                        total_fix_mismatch += 1
                        fix_mismatches.append(
                            {
                                "file": fixture_path.name,
                                "case": case["name"],
                                "rule": rule_code,
                                "dialect": sqlfluff_dialect,
                                "input": sql.strip()[:100],
                                "expected": expected.strip()[:100],
                                "got": (
                                    fs_fixed.strip()[:100]
                                    if fs_fixed
                                    else "(fix failed)"
                                ),
                            }
                        )

        rule_results[f"{rule_code} ({fixture_path.stem})"] = {
            "pass_ok": r_pass_ok,
            "pass_bad": r_pass_bad,
            "fail_ok": r_fail_ok,
            "fail_bad": r_fail_bad,
            "fix_ok": r_fix_ok,
            "fix_bad": r_fix_bad,
            "fix_total": r_fix_total,
            "skip": r_skip,
        }

    elapsed = time.time() - start_time

    # ------------------------------------------------------------------
    # Print report
    # ------------------------------------------------------------------

    sep = "=" * 80
    thin = "-" * 80

    print(sep)
    print("FLOWSCOPE vs SQLFLUFF FIXTURE PARITY REPORT")
    print(sep)
    print(f"\nSQLFluff source: {sqlfluff_dir}")
    print(f"Fixtures:        {len(fixture_files)} YAML files")
    print(f"Cases evaluated: {total_cases}")
    print(f"Skipped (dialect): {total_skipped_dialect}")
    print(f"Elapsed:         {elapsed:.1f}s\n")

    # --- Detection summary ---
    print(thin)
    print("DETECTION AGREEMENT")
    print(thin)
    total_pass = total_pass_agree + total_pass_disagree
    total_fail = total_fail_agree + total_fail_disagree
    overall = total_pass_agree + total_fail_agree

    def pct(n: int, d: int) -> str:
        return f"{100 * n / d:.1f}%" if d else "n/a"

    print(f"\n  Pass (no violation expected):   {total_pass_agree}/{total_pass} ({pct(total_pass_agree, total_pass)})")
    print(f"  False positives:               {total_pass_disagree}/{total_pass} ({pct(total_pass_disagree, total_pass)})")
    print(f"\n  Fail (violation expected):      {total_fail_agree}/{total_fail} ({pct(total_fail_agree, total_fail)})")
    print(f"  False negatives:               {total_fail_disagree}/{total_fail} ({pct(total_fail_disagree, total_fail)})")
    print(f"\n  Overall agreement:             {overall}/{total_cases} ({pct(overall, total_cases)})")

    # --- Fix summary ---
    print(f"\n{thin}")
    print("FIX OUTPUT (normalized whitespace comparison)")
    print(thin)
    print(f"\n  Cases with fix_str: {total_fix_cases}")
    print(f"  Match:              {total_fix_match}/{total_fix_cases} ({pct(total_fix_match, total_fix_cases)})")
    print(f"  Mismatch:           {total_fix_mismatch}/{total_fix_cases} ({pct(total_fix_mismatch, total_fix_cases)})")

    # --- Per-rule table ---
    print(f"\n{sep}")
    print("PER-RULE BREAKDOWN")
    print(sep)
    header = f"{'Rule':<25} {'Pass':<12} {'Fail':<12} {'Fix':<12} {'Skip':<6}"
    subhdr = f"{'':<25} {'ok/tot':<12} {'ok/tot':<12} {'ok/tot':<12} {'dial':<6}"
    print(f"\n{header}")
    print(subhdr)
    print("-" * 67)
    for key in sorted(rule_results):
        r = rule_results[key]
        pt = r["pass_ok"] + r["pass_bad"]
        ft = r["fail_ok"] + r["fail_bad"]
        ps = f"{r['pass_ok']}/{pt}" if pt else "-"
        fs = f"{r['fail_ok']}/{ft}" if ft else "-"
        xs = f"{r['fix_ok']}/{r['fix_total']}" if r["fix_total"] else "-"
        sk = str(r["skip"]) if r["skip"] else "-"
        print(f"{key:<25} {ps:<12} {fs:<12} {xs:<12} {sk:<6}")

    # --- Detection disagreements ---
    if detection_disagreements:
        print(f"\n{sep}")
        print(f"DETECTION DISAGREEMENTS ({len(detection_disagreements)} cases)")
        print(sep)
        for d in detection_disagreements:
            tag = "FALSE_POS" if d["type"] == "false_positive" else "FALSE_NEG"
            print(
                f"\n  [{tag}] {d['file']}::{d['case']} "
                f"(rule={d['rule']}, dialect={d['dialect']})"
            )
            print(f"    SQL: {d['sql']}")
            if d["type"] == "false_positive":
                print(f"    FlowScope reported: {d.get('fs_codes', [])}")

    # --- Fix mismatches ---
    if fix_mismatches:
        print(f"\n{sep}")
        print(f"FIX MISMATCHES ({len(fix_mismatches)} cases)")
        print(sep)
        for m in fix_mismatches:
            print(
                f"\n  {m['file']}::{m['case']} "
                f"(rule={m['rule']}, dialect={m['dialect']})"
            )
            print(f"    Input:    {m['input']}")
            print(f"    Expected: {m['expected']}")
            print(f"    Got:      {m['got']}")

    print(f"\n{sep}")
    print("END OF REPORT")
    print(sep)


if __name__ == "__main__":
    main()
