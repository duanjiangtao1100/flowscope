#!/usr/bin/env python3
"""Compare FlowScope vs SQLFluff lint/fix behavior on a real SQL corpus.

This script runs both tools on the same copied corpus and reports:
- before/after total violations
- per-rule before/after deltas for both tools
- parity gap by rule (how much SQLFluff reduced vs FlowScope reduced)
- FlowScope fix telemetry (applied/skipped/blocked candidate breakdown)
- SQLFluff fixability summary from lint JSON + fix command output summary

Example:
  python3 scripts/sql-corpus-parity-report.py \
      --sql-dir /tmp/sql2 \
      --sqlfluff-bin /path/to/sqlfluff \
      --dialect postgres
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLOWSCOPE_BIN = REPO_ROOT / "target" / "release" / "flowscope"


@dataclass
class FlowScopeFixTelemetry:
    applied: int = 0
    modified_inputs: int = 0
    skipped_comments: int = 0
    skipped_regression: int = 0
    skipped_parse_errors: int = 0
    candidates_total: int = 0
    candidates_skipped: int = 0
    candidates_blocked: int = 0
    blocked_unsafe: int = 0
    blocked_display_only: int = 0
    blocked_protected_range: int = 0
    blocked_overlap_conflict: int = 0


@dataclass
class SqlfluffFixTelemetry:
    fixable_reported: int = 0
    unfixable_reported: int = 0


def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _require_executable(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if not os.access(path, os.X_OK):
        raise PermissionError(f"{label} is not executable: {path}")


def _collect_sql_files(sql_dir: Path) -> list[Path]:
    return sorted(p for p in sql_dir.rglob("*.sql") if p.is_file())


def _parse_flowscope_counts(lint_json: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    if not lint_json.strip():
        return counts
    data = json.loads(lint_json)
    for file_result in data:
        for violation in file_result.get("violations", []):
            code = violation.get("code")
            if code:
                counts[code] += 1
    return counts


def _parse_sqlfluff_counts_and_fixability(
    lint_json: str,
) -> tuple[Counter[str], Counter[str], Counter[str]]:
    counts: Counter[str] = Counter()
    fixable: Counter[str] = Counter()
    unfixable: Counter[str] = Counter()

    if not lint_json.strip():
        return counts, fixable, unfixable

    data = json.loads(lint_json)
    for file_result in data:
        for violation in file_result.get("violations", []):
            code = violation.get("code")
            if not code:
                continue
            counts[code] += 1
            fixes = violation.get("fixes") or []
            if len(fixes) > 0:
                fixable[code] += 1
            else:
                unfixable[code] += 1

    return counts, fixable, unfixable


def _run_flowscope_lint(flowscope_bin: Path, dialect: str, sql_dir: Path) -> Counter[str]:
    cmd = [
        str(flowscope_bin),
        "--dialect",
        dialect,
        "--lint",
        "--format",
        "json",
        str(sql_dir),
    ]
    result = _run(cmd)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"FlowScope lint failed with exit={result.returncode}:\n{result.stderr}"
        )
    return _parse_flowscope_counts(result.stdout)


def _run_flowscope_fix(
    flowscope_bin: Path,
    dialect: str,
    sql_dir: Path,
    unsafe_fixes: bool,
    legacy_ast_fixes: bool,
) -> tuple[FlowScopeFixTelemetry, str, str]:
    cmd = [
        str(flowscope_bin),
        "--dialect",
        dialect,
        "--lint",
        "--fix",
        "--show-fixes",
        str(sql_dir),
    ]
    if unsafe_fixes:
        cmd.append("--unsafe-fixes")
    if legacy_ast_fixes:
        cmd.append("--legacy-ast-fixes")

    result = _run(cmd, timeout=600)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"FlowScope fix failed with exit={result.returncode}:\n{result.stderr}"
        )

    telemetry = _parse_flowscope_fix_stderr(result.stderr)
    return telemetry, result.stdout, result.stderr


def _parse_flowscope_fix_stderr(stderr: str) -> FlowScopeFixTelemetry:
    telemetry = FlowScopeFixTelemetry()

    m = re.search(r"applied\s+(\d+)\s+auto-fix\(es\)\s+across\s+(\d+)\s+input\(s\)", stderr)
    if m:
        telemetry.applied = int(m.group(1))
        telemetry.modified_inputs = int(m.group(2))

    patterns = [
        (r"skipped auto-fix for\s+(\d+)\s+input\(s\) because comments are present", "skipped_comments"),
        (
            r"skipped auto-fix for\s+(\d+)\s+input\(s\) because fixes increased total violations",
            "skipped_regression",
        ),
        (r"skipped auto-fix for\s+(\d+)\s+input\(s\) due to parse errors", "skipped_parse_errors"),
    ]
    for pattern, field in patterns:
        m = re.search(pattern, stderr)
        if m:
            setattr(telemetry, field, int(m.group(1)))

    m = re.search(
        r"skipped/blocked fix candidates:\s+(\d+)\s+\(skipped:\s+(\d+),\s+blocked:\s+(\d+),\s+unsafe blocked:\s+(\d+),\s+display-only blocked:\s+(\d+)(?:,\s+protected-range blocked:\s+(\d+),\s+overlap-conflict blocked:\s+(\d+))?\)",
        stderr,
    )
    if m:
        telemetry.candidates_total = int(m.group(1))
        telemetry.candidates_skipped = int(m.group(2))
        telemetry.candidates_blocked = int(m.group(3))
        telemetry.blocked_unsafe = int(m.group(4))
        telemetry.blocked_display_only = int(m.group(5))
        telemetry.blocked_protected_range = int(m.group(6) or 0)
        telemetry.blocked_overlap_conflict = int(m.group(7) or 0)

    return telemetry


def _run_sqlfluff_lint(
    sqlfluff_bin: Path,
    dialect: str,
    sql_dir: Path,
) -> tuple[Counter[str], Counter[str], Counter[str], str, str]:
    cmd = [
        str(sqlfluff_bin),
        "lint",
        "--dialect",
        dialect,
        "--format",
        "json",
        str(sql_dir),
    ]
    result = _run(cmd, timeout=600)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"SQLFluff lint failed with exit={result.returncode}:\n{result.stderr}"
        )

    counts, fixable, unfixable = _parse_sqlfluff_counts_and_fixability(result.stdout)
    return counts, fixable, unfixable, result.stdout, result.stderr


def _run_sqlfluff_fix(
    sqlfluff_bin: Path,
    dialect: str,
    sql_dir: Path,
) -> tuple[SqlfluffFixTelemetry, str, str]:
    cmd = [
        str(sqlfluff_bin),
        "fix",
        "--dialect",
        dialect,
        "--force",
        str(sql_dir),
    ]
    result = _run(cmd, timeout=900)
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"SQLFluff fix failed with exit={result.returncode}:\n{result.stderr}"
        )

    output = (result.stdout or "") + "\n" + (result.stderr or "")
    telemetry = SqlfluffFixTelemetry()

    m = re.search(r"(\d+)\s+fixable linting violations found", output)
    if m:
        telemetry.fixable_reported = int(m.group(1))

    m = re.search(r"\[(\d+)\s+unfixable linting violations found\]", output)
    if m:
        telemetry.unfixable_reported = int(m.group(1))

    return telemetry, result.stdout, result.stderr


def _sum_counts(counts: Counter[str]) -> int:
    return int(sum(counts.values()))


def _rule_delta(before: int, after: int) -> int:
    return after - before


def _rule_reduced(before: int, after: int) -> int:
    return max(before - after, 0)


def _print_table(rows: list[tuple], headers: tuple[str, ...]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(str(value)))

    fmt = "  " + "  ".join("{" + f":<{w}" + "}" for w in widths)
    print(fmt.format(*headers))
    print("  " + "  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*row))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sql-dir", type=Path, required=True, help="Directory containing .sql files")
    parser.add_argument(
        "--flowscope-bin",
        type=Path,
        default=DEFAULT_FLOWSCOPE_BIN,
        help=f"Path to flowscope binary (default: {DEFAULT_FLOWSCOPE_BIN})",
    )
    parser.add_argument("--sqlfluff-bin", type=Path, required=True, help="Path to sqlfluff binary")
    parser.add_argument("--dialect", default="postgres", help="SQL dialect for both tools")
    parser.add_argument("--unsafe-fixes", action="store_true", help="Pass --unsafe-fixes to FlowScope")
    parser.add_argument(
        "--legacy-ast-fixes",
        action="store_true",
        help="Pass --legacy-ast-fixes to FlowScope",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Optional persistent work directory (otherwise a temp dir is used)",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=None,
        help="Optional path to write the full report JSON",
    )

    args = parser.parse_args()

    sql_dir = args.sql_dir.resolve()
    flowscope_bin = args.flowscope_bin.resolve()
    sqlfluff_bin = args.sqlfluff_bin.resolve()

    if not sql_dir.is_dir():
        raise SystemExit(f"SQL directory not found: {sql_dir}")

    _require_executable(flowscope_bin, "FlowScope binary")
    _require_executable(sqlfluff_bin, "SQLFluff binary")

    sql_files = _collect_sql_files(sql_dir)
    if not sql_files:
        raise SystemExit(f"No .sql files found under: {sql_dir}")

    temp_ctx = None
    if args.work_dir is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix="flowscope_sql_corpus_parity_")
        work_root = Path(temp_ctx.name)
    else:
        work_root = args.work_dir.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    fs_probe = work_root / "flowscope_probe"
    sf_probe = work_root / "sqlfluff_probe"

    if fs_probe.exists():
        shutil.rmtree(fs_probe)
    if sf_probe.exists():
        shutil.rmtree(sf_probe)

    shutil.copytree(sql_dir, fs_probe)
    shutil.copytree(sql_dir, sf_probe)

    started_at = time.time()

    fs_before = _run_flowscope_lint(flowscope_bin, args.dialect, fs_probe)
    fs_fix_telemetry, fs_fix_stdout, fs_fix_stderr = _run_flowscope_fix(
        flowscope_bin,
        args.dialect,
        fs_probe,
        args.unsafe_fixes,
        args.legacy_ast_fixes,
    )
    fs_after = _run_flowscope_lint(flowscope_bin, args.dialect, fs_probe)

    sf_before, sf_fixable_by_rule, sf_unfixable_by_rule, sf_lint_before_stdout, sf_lint_before_stderr = _run_sqlfluff_lint(
        sqlfluff_bin,
        args.dialect,
        sf_probe,
    )
    sf_fix_telemetry, sf_fix_stdout, sf_fix_stderr = _run_sqlfluff_fix(
        sqlfluff_bin,
        args.dialect,
        sf_probe,
    )
    sf_after, _, _, sf_lint_after_stdout, sf_lint_after_stderr = _run_sqlfluff_lint(
        sqlfluff_bin,
        args.dialect,
        sf_probe,
    )

    elapsed = time.time() - started_at

    fs_total_before = _sum_counts(fs_before)
    fs_total_after = _sum_counts(fs_after)
    sf_total_before = _sum_counts(sf_before)
    sf_total_after = _sum_counts(sf_after)

    all_rules = sorted(set(fs_before) | set(fs_after) | set(sf_before) | set(sf_after))
    rows = []
    for rule in all_rules:
        fs_b = int(fs_before.get(rule, 0))
        fs_a = int(fs_after.get(rule, 0))
        sf_b = int(sf_before.get(rule, 0))
        sf_a = int(sf_after.get(rule, 0))

        fs_delta = _rule_delta(fs_b, fs_a)
        sf_delta = _rule_delta(sf_b, sf_a)
        fs_reduced = _rule_reduced(fs_b, fs_a)
        sf_reduced = _rule_reduced(sf_b, sf_a)
        parity_gap = sf_reduced - fs_reduced

        rows.append(
            (
                rule,
                fs_b,
                fs_a,
                f"{fs_delta:+d}",
                sf_b,
                sf_a,
                f"{sf_delta:+d}",
                int(sf_fixable_by_rule.get(rule, 0)),
                int(sf_unfixable_by_rule.get(rule, 0)),
                parity_gap,
            )
        )

    top_gap_rows = sorted(rows, key=lambda r: r[9], reverse=True)
    top_gap_rows = [r for r in top_gap_rows if r[9] > 0][:20]

    print("=" * 100)
    print("FLOW SCOPE vs SQLFLUFF CORPUS PARITY (LINT+FIX)")
    print("=" * 100)
    print(f"SQL dir:        {sql_dir}")
    print(f"FlowScope bin:  {flowscope_bin}")
    print(f"SQLFluff bin:   {sqlfluff_bin}")
    print(f"Dialect:        {args.dialect}")
    print(f"Files:          {len(sql_files)}")
    print(f"Work dir:       {work_root}")
    print(f"Elapsed:        {elapsed:.2f}s")

    print("\n" + "-" * 100)
    print("TOTAL VIOLATIONS")
    print("-" * 100)
    print(f"FlowScope: {fs_total_before} -> {fs_total_after} ({fs_total_after - fs_total_before:+d})")
    print(f"SQLFluff:  {sf_total_before} -> {sf_total_after} ({sf_total_after - sf_total_before:+d})")

    print("\n" + "-" * 100)
    print("FLOWSCOPE FIX TELEMETRY")
    print("-" * 100)
    print(
        "  applied={applied} modified_inputs={modified_inputs} "
        "skipped_comments={skipped_comments} skipped_regression={skipped_regression} "
        "skipped_parse_errors={skipped_parse_errors}".format(**asdict(fs_fix_telemetry))
    )
    print(
        "  candidates total={candidates_total} skipped={candidates_skipped} blocked={candidates_blocked} "
        "unsafe={blocked_unsafe} display_only={blocked_display_only} "
        "protected_range={blocked_protected_range} overlap_conflict={blocked_overlap_conflict}".format(
            **asdict(fs_fix_telemetry)
        )
    )

    print("\n" + "-" * 100)
    print("SQLFLUFF FIX TELEMETRY")
    print("-" * 100)
    print(
        f"  reported fixable={sf_fix_telemetry.fixable_reported} "
        f"reported unfixable={sf_fix_telemetry.unfixable_reported}"
    )

    if top_gap_rows:
        print("\n" + "-" * 100)
        print("TOP PARITY GAPS (SQLFLuff reduction - FlowScope reduction)")
        print("-" * 100)
        _print_table(
            [
                (
                    r[0],
                    r[1],
                    r[2],
                    r[4],
                    r[5],
                    r[7],
                    r[8],
                    r[9],
                )
                for r in top_gap_rows
            ],
            (
                "RULE",
                "FS_BEFORE",
                "FS_AFTER",
                "SF_BEFORE",
                "SF_AFTER",
                "SF_FIXABLE",
                "SF_UNFIXABLE",
                "GAP",
            ),
        )

    print("\n" + "-" * 100)
    print("FULL RULE DELTA TABLE")
    print("-" * 100)
    _print_table(
        rows,
        (
            "RULE",
            "FS_BEFORE",
            "FS_AFTER",
            "FS_DELTA",
            "SF_BEFORE",
            "SF_AFTER",
            "SF_DELTA",
            "SF_FIXABLE",
            "SF_UNFIXABLE",
            "GAP",
        ),
    )

    report = {
        "meta": {
            "sql_dir": str(sql_dir),
            "flowscope_bin": str(flowscope_bin),
            "sqlfluff_bin": str(sqlfluff_bin),
            "dialect": args.dialect,
            "files": len(sql_files),
            "work_dir": str(work_root),
            "elapsed_seconds": elapsed,
            "flowscope_flags": {
                "unsafe_fixes": args.unsafe_fixes,
                "legacy_ast_fixes": args.legacy_ast_fixes,
            },
        },
        "totals": {
            "flowscope_before": fs_total_before,
            "flowscope_after": fs_total_after,
            "flowscope_delta": fs_total_after - fs_total_before,
            "sqlfluff_before": sf_total_before,
            "sqlfluff_after": sf_total_after,
            "sqlfluff_delta": sf_total_after - sf_total_before,
        },
        "flowscope_fix_telemetry": asdict(fs_fix_telemetry),
        "sqlfluff_fix_telemetry": asdict(sf_fix_telemetry),
        "rules": [
            {
                "rule": r[0],
                "flowscope_before": r[1],
                "flowscope_after": r[2],
                "flowscope_delta": int(str(r[3])),
                "sqlfluff_before": r[4],
                "sqlfluff_after": r[5],
                "sqlfluff_delta": int(str(r[6])),
                "sqlfluff_fixable": r[7],
                "sqlfluff_unfixable": r[8],
                "parity_gap": r[9],
            }
            for r in rows
        ],
        "raw": {
            "flowscope_fix_stdout": fs_fix_stdout,
            "flowscope_fix_stderr": fs_fix_stderr,
            "sqlfluff_fix_stdout": sf_fix_stdout,
            "sqlfluff_fix_stderr": sf_fix_stderr,
            "sqlfluff_lint_before_stderr": sf_lint_before_stderr,
            "sqlfluff_lint_after_stderr": sf_lint_after_stderr,
            "sqlfluff_lint_before_stdout": sf_lint_before_stdout,
            "sqlfluff_lint_after_stdout": sf_lint_after_stdout,
        },
    }

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(report, indent=2))
        print(f"\nJSON report written to: {args.json_output}")

    if temp_ctx is not None:
        temp_ctx.cleanup()


if __name__ == "__main__":
    main()
