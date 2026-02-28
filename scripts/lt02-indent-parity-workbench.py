#!/usr/bin/env python3
"""LT02-focused corpus parity workbench for FlowScope vs SQLFluff.

Runs both tools in LT02-only mode on a copied SQL corpus, applies fixes, and
reports:
- LT02 before/after counts
- parity gap after fix
- FlowScope fix telemetry
- grouped residual LT02 issues in FlowScope after fix
- per-file/line divergences vs SQLFluff after fix

Example:
  python3 scripts/lt02-indent-parity-workbench.py \
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
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FLOWSCOPE_BIN = REPO_ROOT / "target" / "release" / "flowscope"
TARGET_RULE = "LT02"
ALL_RULE_CODES: set[str] = {
    "AM01",
    "AM02",
    "AM03",
    "AM04",
    "AM05",
    "AM06",
    "AM07",
    "AM08",
    "AM09",
    "CP01",
    "CP02",
    "CP03",
    "CP04",
    "CP05",
    "CV01",
    "CV02",
    "CV03",
    "CV04",
    "CV05",
    "CV06",
    "CV07",
    "CV08",
    "CV09",
    "CV10",
    "CV11",
    "CV12",
    "JJ01",
    "LT01",
    "LT02",
    "LT03",
    "LT04",
    "LT05",
    "LT06",
    "LT07",
    "LT08",
    "LT09",
    "LT10",
    "LT11",
    "LT12",
    "LT13",
    "LT14",
    "LT15",
    "RF01",
    "RF02",
    "RF03",
    "RF04",
    "RF05",
    "RF06",
    "ST01",
    "ST02",
    "ST03",
    "ST04",
    "ST05",
    "ST06",
    "ST07",
    "ST08",
    "ST09",
    "ST10",
    "ST11",
    "ST12",
    "AL01",
    "AL02",
    "AL03",
    "AL04",
    "AL05",
    "AL06",
    "AL07",
    "AL08",
    "AL09",
    "TQ01",
    "TQ02",
    "TQ03",
}


@dataclass(frozen=True)
class RuleViolation:
    relpath: str
    line: int
    column: int


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


def _run(cmd: list[str], timeout: int = 900) -> subprocess.CompletedProcess[str]:
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


def _json_array_from_output(output: str) -> list[dict]:
    text = output.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1 or end < start:
            raise
        data = json.loads(text[start : end + 1])
    if not isinstance(data, list):
        raise ValueError("Expected JSON array output")
    return data


def _relpath(path_value: str, root: Path) -> str:
    p = Path(path_value)
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except Exception:
        return p.name


def _parse_flowscope_lt02(lint_json: str, root: Path) -> list[RuleViolation]:
    violations: list[RuleViolation] = []
    for file_result in _json_array_from_output(lint_json):
        relpath = _relpath(str(file_result.get("file", "")), root)
        for issue in file_result.get("violations", []):
            if str(issue.get("code", "")).upper() != TARGET_RULE:
                continue
            line = int(issue.get("line") or 0)
            col = int(issue.get("column") or 0)
            violations.append(RuleViolation(relpath=relpath, line=line, column=col))
    return violations


def _flowscope_exclude_rules_for_lt02() -> str:
    return ",".join(sorted(ALL_RULE_CODES - {TARGET_RULE}))


def _parse_sqlfluff_lt02(lint_json: str, root: Path) -> tuple[list[RuleViolation], int, int]:
    violations: list[RuleViolation] = []
    fixable = 0
    unfixable = 0
    for file_result in _json_array_from_output(lint_json):
        relpath = _relpath(str(file_result.get("filepath", "")), root)
        for issue in file_result.get("violations", []):
            if str(issue.get("code", "")).upper() != TARGET_RULE:
                continue
            line = int(issue.get("start_line_no") or 0)
            col = int(issue.get("start_line_pos") or 0)
            fixes = issue.get("fixes") or []
            if fixes:
                fixable += 1
            else:
                unfixable += 1
            violations.append(RuleViolation(relpath=relpath, line=line, column=col))
    return violations, fixable, unfixable


def _run_flowscope_lint(flowscope_bin: Path, dialect: str, sql_dir: Path) -> tuple[list[RuleViolation], str]:
    cmd = [
        str(flowscope_bin),
        "--dialect",
        dialect,
        "--lint",
        "--exclude-rules",
        _flowscope_exclude_rules_for_lt02(),
        "--format",
        "json",
        str(sql_dir),
    ]
    result = _run(cmd, timeout=600)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"FlowScope LT02 lint failed ({result.returncode}):\n{result.stderr}")
    return _parse_flowscope_lt02(result.stdout, sql_dir), result.stderr


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


def _run_flowscope_fix(
    flowscope_bin: Path,
    dialect: str,
    sql_dir: Path,
    unsafe_fixes: bool,
) -> tuple[FlowScopeFixTelemetry, str, str]:
    cmd = [
        str(flowscope_bin),
        "--dialect",
        dialect,
        "--lint",
        "--fix",
        "--show-fixes",
        "--exclude-rules",
        _flowscope_exclude_rules_for_lt02(),
        str(sql_dir),
    ]
    if unsafe_fixes:
        cmd.append("--unsafe-fixes")

    result = _run(cmd, timeout=900)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"FlowScope LT02 fix failed ({result.returncode}):\n{result.stderr}")
    return _parse_flowscope_fix_stderr(result.stderr), result.stdout, result.stderr


def _run_sqlfluff_lint(
    sqlfluff_bin: Path,
    dialect: str,
    sql_dir: Path,
) -> tuple[list[RuleViolation], int, int, str, str]:
    cmd = [
        str(sqlfluff_bin),
        "lint",
        "--dialect",
        dialect,
        "--rules",
        TARGET_RULE,
        "--format",
        "json",
        str(sql_dir),
    ]
    result = _run(cmd, timeout=900)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"SQLFluff LT02 lint failed ({result.returncode}):\n{result.stderr}")
    violations, fixable, unfixable = _parse_sqlfluff_lt02(result.stdout, sql_dir)
    return violations, fixable, unfixable, result.stdout, result.stderr


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
        "--rules",
        TARGET_RULE,
        "--force",
        str(sql_dir),
    ]
    result = _run(cmd, timeout=1200)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"SQLFluff LT02 fix failed ({result.returncode}):\n{result.stderr}")

    telemetry = SqlfluffFixTelemetry()
    output = f"{result.stdout}\n{result.stderr}"
    m = re.search(r"(\d+)\s+fixable linting violations found", output)
    if m:
        telemetry.fixable_reported = int(m.group(1))
    m = re.search(r"\[(\d+)\s+unfixable linting violations found\]", output)
    if m:
        telemetry.unfixable_reported = int(m.group(1))
    return telemetry, result.stdout, result.stderr


def _clip(text: str, max_len: int = 120) -> str:
    text = text.rstrip("\n")
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _leading_ws(line: str) -> str:
    m = re.match(r"^[ \t]*", line)
    return m.group(0) if m else ""


def _previous_non_blank(lines: list[str], idx: int) -> str:
    i = idx - 1
    while i >= 0:
        if lines[i].strip():
            return lines[i]
        i -= 1
    return ""


def _classify_lt02_residual(line_text: str, previous_non_blank: str) -> str:
    stripped = line_text.strip()
    upper = stripped.upper()
    ws = _leading_ws(line_text)

    if not stripped:
        return "blank-line"
    if "{{" in line_text or "{%" in line_text or "}}" in line_text or "%}" in line_text:
        return "templated-line"
    if stripped.startswith("--") or stripped.startswith("/*") or stripped.startswith("*"):
        return "comment-line"
    if " " in ws and "\t" in ws:
        return "mixed-tabs-spaces"
    if "\t" in ws:
        return "tab-indentation"
    if stripped.startswith(")") or stripped.startswith("],") or stripped.startswith("),"):
        return "closing-bracket-alignment"
    if upper.startswith(("CASE", "WHEN ", "THEN", "ELSE", "END")):
        return "case-block"
    if upper.startswith(
        ("JOIN ", "LEFT JOIN ", "RIGHT JOIN ", "FULL JOIN ", "INNER JOIN ", "CROSS JOIN ", "ON ", "USING ")
    ):
        return "join-on-block"
    if upper.startswith(("UNION", "INTERSECT", "EXCEPT")):
        return "set-operator-block"
    prev = previous_non_blank.rstrip()
    if prev.endswith("(") or prev.endswith(","):
        return "continuation-hanging-indent"
    if upper.startswith(
        ("SELECT", "FROM", "WHERE", "HAVING", "GROUP BY", "ORDER BY", "LIMIT", "OFFSET", "WITH", "UPDATE", "INSERT")
    ):
        return "clause-alignment"
    return "general-structural"


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
        "--work-dir",
        type=Path,
        default=None,
        help="Optional persistent work directory (otherwise a temp dir is used)",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=40,
        help="Max LT02 residual line samples to print",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=None,
        help="Optional path for full JSON report",
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
        temp_ctx = tempfile.TemporaryDirectory(prefix="flowscope_lt02_parity_")
        work_root = Path(temp_ctx.name)
    else:
        work_root = args.work_dir.resolve()
        work_root.mkdir(parents=True, exist_ok=True)

    fs_probe = work_root / "flowscope"
    sf_probe = work_root / "sqlfluff"
    if fs_probe.exists():
        shutil.rmtree(fs_probe)
    if sf_probe.exists():
        shutil.rmtree(sf_probe)
    shutil.copytree(sql_dir, fs_probe)
    shutil.copytree(sql_dir, sf_probe)

    started_at = time.time()

    fs_before, fs_lint_before_stderr = _run_flowscope_lint(flowscope_bin, args.dialect, fs_probe)
    fs_fix_telemetry, fs_fix_stdout, fs_fix_stderr = _run_flowscope_fix(
        flowscope_bin,
        args.dialect,
        fs_probe,
        args.unsafe_fixes,
    )
    fs_after, fs_lint_after_stderr = _run_flowscope_lint(flowscope_bin, args.dialect, fs_probe)

    sf_before, sf_fixable_before, sf_unfixable_before, sf_lint_before_stdout, sf_lint_before_stderr = _run_sqlfluff_lint(
        sqlfluff_bin, args.dialect, sf_probe
    )
    sf_fix_telemetry, sf_fix_stdout, sf_fix_stderr = _run_sqlfluff_fix(
        sqlfluff_bin,
        args.dialect,
        sf_probe,
    )
    sf_after, sf_fixable_after, sf_unfixable_after, sf_lint_after_stdout, sf_lint_after_stderr = _run_sqlfluff_lint(
        sqlfluff_bin, args.dialect, sf_probe
    )

    elapsed = time.time() - started_at

    fs_before_count = len(fs_before)
    fs_after_count = len(fs_after)
    sf_before_count = len(sf_before)
    sf_after_count = len(sf_after)

    fs_reduced = max(fs_before_count - fs_after_count, 0)
    sf_reduced = max(sf_before_count - sf_after_count, 0)
    gap_after = sf_reduced - fs_reduced

    fs_after_set = {(v.relpath, v.line, v.column) for v in fs_after}
    sf_after_set = {(v.relpath, v.line, v.column) for v in sf_after}
    fs_only_after = sorted(fs_after_set - sf_after_set)
    sf_only_after = sorted(sf_after_set - fs_after_set)

    bucket_counts: Counter[str] = Counter()
    bucket_samples: defaultdict[str, list[dict]] = defaultdict(list)
    by_file_counts: Counter[str] = Counter(v.relpath for v in fs_after)
    for violation in fs_after:
        file_path = fs_probe / violation.relpath
        if not file_path.exists():
            continue
        lines = file_path.read_text(errors="replace").splitlines()
        idx = max(violation.line - 1, 0)
        line_text = lines[idx] if idx < len(lines) else ""
        prev = _previous_non_blank(lines, idx)
        bucket = _classify_lt02_residual(line_text, prev)
        bucket_counts[bucket] += 1
        if len(bucket_samples[bucket]) < 8:
            bucket_samples[bucket].append(
                {
                    "file": violation.relpath,
                    "line": violation.line,
                    "column": violation.column,
                    "text": _clip(line_text),
                }
            )

    print("=" * 100)
    print("LT02 INDENTATION PARITY WORKBENCH")
    print("=" * 100)
    print(f"SQL dir:        {sql_dir}")
    print(f"FlowScope bin:  {flowscope_bin}")
    print(f"SQLFluff bin:   {sqlfluff_bin}")
    print(f"Dialect:        {args.dialect}")
    print(f"Files:          {len(sql_files)}")
    print(f"Work dir:       {work_root}")
    print(f"Elapsed:        {elapsed:.2f}s")

    print("\n" + "-" * 100)
    print("LT02 TOTALS")
    print("-" * 100)
    print(f"FlowScope LT02: {fs_before_count} -> {fs_after_count} ({fs_after_count - fs_before_count:+d})")
    print(f"SQLFluff LT02:  {sf_before_count} -> {sf_after_count} ({sf_after_count - sf_before_count:+d})")
    print(f"Parity gap:     {gap_after} (SQLFluff reduction - FlowScope reduction)")

    print("\n" + "-" * 100)
    print("FIXABILITY TELEMETRY")
    print("-" * 100)
    print(
        "FlowScope  applied={applied} modified_inputs={modified_inputs} "
        "skipped_comments={skipped_comments} skipped_regression={skipped_regression} "
        "skipped_parse_errors={skipped_parse_errors}".format(**asdict(fs_fix_telemetry))
    )
    print(
        "FlowScope  candidates total={candidates_total} skipped={candidates_skipped} blocked={candidates_blocked} "
        "unsafe={blocked_unsafe} display_only={blocked_display_only} "
        "protected_range={blocked_protected_range} overlap_conflict={blocked_overlap_conflict}".format(
            **asdict(fs_fix_telemetry)
        )
    )
    print(
        f"SQLFluff   lint_before fixable={sf_fixable_before} unfixable={sf_unfixable_before} "
        f"lint_after fixable={sf_fixable_after} unfixable={sf_unfixable_after}"
    )
    print(
        f"SQLFluff   fix command reported fixable={sf_fix_telemetry.fixable_reported} "
        f"unfixable={sf_fix_telemetry.unfixable_reported}"
    )

    if by_file_counts:
        print("\n" + "-" * 100)
        print("TOP FILES WITH FLOW SCOPE LT02 RESIDUALS")
        print("-" * 100)
        for relpath, count in by_file_counts.most_common(12):
            print(f"  {count:4d}  {relpath}")

    if bucket_counts:
        print("\n" + "-" * 100)
        print("FLOW SCOPE LT02 RESIDUAL GROUPS")
        print("-" * 100)
        for bucket, count in bucket_counts.most_common():
            print(f"  {count:4d}  {bucket}")

        print("\n" + "-" * 100)
        print("RESIDUAL LT02 SAMPLES")
        print("-" * 100)
        emitted = 0
        for bucket, _count in bucket_counts.most_common():
            for sample in bucket_samples[bucket]:
                print(
                    f"  {sample['file']}:{sample['line']}:{sample['column']}  [{bucket}]  {sample['text']}"
                )
                emitted += 1
                if emitted >= max(args.sample_limit, 0):
                    break
            if emitted >= max(args.sample_limit, 0):
                break

    if fs_only_after or sf_only_after:
        print("\n" + "-" * 100)
        print("AFTER-FIX LT02 DIVERGENCE SETS")
        print("-" * 100)
        print(f"FlowScope-only after-fix LT02 locations: {len(fs_only_after)}")
        print(f"SQLFluff-only after-fix LT02 locations:  {len(sf_only_after)}")

    report = {
        "meta": {
            "sql_dir": str(sql_dir),
            "flowscope_bin": str(flowscope_bin),
            "sqlfluff_bin": str(sqlfluff_bin),
            "dialect": args.dialect,
            "files": len(sql_files),
            "work_dir": str(work_root),
            "elapsed_seconds": elapsed,
            "rule": TARGET_RULE,
            "flowscope_flags": {"unsafe_fixes": args.unsafe_fixes},
        },
        "totals": {
            "flowscope_before": fs_before_count,
            "flowscope_after": fs_after_count,
            "flowscope_delta": fs_after_count - fs_before_count,
            "sqlfluff_before": sf_before_count,
            "sqlfluff_after": sf_after_count,
            "sqlfluff_delta": sf_after_count - sf_before_count,
            "parity_gap": gap_after,
        },
        "flowscope_fix_telemetry": asdict(fs_fix_telemetry),
        "sqlfluff_fix_telemetry": asdict(sf_fix_telemetry),
        "sqlfluff_lint_fixability": {
            "before_fixable": sf_fixable_before,
            "before_unfixable": sf_unfixable_before,
            "after_fixable": sf_fixable_after,
            "after_unfixable": sf_unfixable_after,
        },
        "after_fix": {
            "flowscope_locations": [asdict(v) for v in fs_after],
            "sqlfluff_locations": [asdict(v) for v in sf_after],
            "flowscope_only_locations": [
                {"relpath": p, "line": line, "column": col} for p, line, col in fs_only_after
            ],
            "sqlfluff_only_locations": [
                {"relpath": p, "line": line, "column": col} for p, line, col in sf_only_after
            ],
            "flowscope_bucket_counts": dict(bucket_counts),
            "flowscope_bucket_samples": dict(bucket_samples),
            "flowscope_top_files": by_file_counts.most_common(50),
        },
        "raw": {
            "flowscope_fix_stdout": fs_fix_stdout,
            "flowscope_fix_stderr": fs_fix_stderr,
            "flowscope_lint_before_stderr": fs_lint_before_stderr,
            "flowscope_lint_after_stderr": fs_lint_after_stderr,
            "sqlfluff_fix_stdout": sf_fix_stdout,
            "sqlfluff_fix_stderr": sf_fix_stderr,
            "sqlfluff_lint_before_stdout": sf_lint_before_stdout,
            "sqlfluff_lint_before_stderr": sf_lint_before_stderr,
            "sqlfluff_lint_after_stdout": sf_lint_after_stdout,
            "sqlfluff_lint_after_stderr": sf_lint_after_stderr,
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
