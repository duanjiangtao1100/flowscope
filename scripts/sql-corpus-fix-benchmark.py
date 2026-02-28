#!/usr/bin/env python3
"""Benchmark FlowScope fix performance on a SQL corpus.

Defaults to batch mode (single CLI invocation over the full directory), which
matches real-world usage and avoids per-file process overhead.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark FlowScope fix performance.")
    parser.add_argument("--sql-dir", type=Path, required=True, help="Directory containing *.sql.")
    parser.add_argument(
        "--flowscope-bin",
        type=Path,
        default=Path("target/release/flowscope"),
        help="Path to flowscope binary (default: target/release/flowscope).",
    )
    parser.add_argument("--dialect", default="postgres", help="SQL dialect (default: postgres).")
    parser.add_argument(
        "--mode",
        choices=["batch", "per-file"],
        default="batch",
        help="Benchmark mode (default: batch).",
    )
    parser.add_argument(
        "--no-show-fixes",
        action="store_true",
        help="Do not pass --show-fixes to flowscope.",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        help="Optional CSV output path for per-file mode timings.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional JSON output path for benchmark summary.",
    )
    return parser.parse_args()


def build_fix_cmd(
    flowscope_bin: Path,
    dialect: str,
    target: Path,
    include_show_fixes: bool,
) -> list[str]:
    cmd = [str(flowscope_bin), "--dialect", dialect, "--lint", "--fix"]
    if include_show_fixes:
        cmd.append("--show-fixes")
    cmd.append(str(target))
    return cmd


def collect_sql_files(sql_dir: Path) -> list[Path]:
    return sorted(path for path in sql_dir.rglob("*.sql") if path.is_file())


def benchmark_batch(
    flowscope_bin: Path,
    dialect: str,
    sql_dir: Path,
    include_show_fixes: bool,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="flowscope_fix_batch_") as temp_dir:
        temp_root = Path(temp_dir)
        probe = temp_root / "probe"
        shutil.copytree(sql_dir, probe)

        cmd = build_fix_cmd(flowscope_bin, dialect, probe, include_show_fixes)
        started = time.perf_counter()
        proc = run(cmd)
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        if proc.returncode not in (0, 1):
            raise RuntimeError(
                f"FlowScope fix failed with exit={proc.returncode}:\n{proc.stderr}"
            )

        return {
            "mode": "batch",
            "elapsed_ms": elapsed_ms,
            "returncode": proc.returncode,
            "stderr": proc.stderr,
        }


def benchmark_per_file(
    flowscope_bin: Path,
    dialect: str,
    sql_dir: Path,
    include_show_fixes: bool,
) -> dict:
    rows: list[tuple[str, float]] = []
    files = collect_sql_files(sql_dir)
    for src in files:
        with tempfile.TemporaryDirectory(prefix="flowscope_fix_file_") as temp_dir:
            temp_root = Path(temp_dir)
            dst = temp_root / src.name
            shutil.copy2(src, dst)
            cmd = build_fix_cmd(flowscope_bin, dialect, dst, include_show_fixes)

            started = time.perf_counter()
            proc = run(cmd)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if proc.returncode not in (0, 1):
                raise RuntimeError(
                    f"FlowScope fix failed for {src.name} with exit={proc.returncode}:\n{proc.stderr}"
                )
            rows.append((src.name, elapsed_ms))

    rows.sort(key=lambda item: item[1], reverse=True)
    total_ms = sum(ms for _, ms in rows)
    return {
        "mode": "per-file",
        "elapsed_ms": total_ms,
        "files": len(rows),
        "rows": rows,
    }


def write_per_file_csv(rows: list[tuple[str, float]], csv_output: Path) -> None:
    csv_output.parent.mkdir(parents=True, exist_ok=True)
    with csv_output.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["file", "ms"])
        for name, ms in rows:
            writer.writerow([name, f"{ms:.3f}"])


def main() -> None:
    args = parse_args()
    sql_dir = args.sql_dir.resolve()
    flowscope_bin = args.flowscope_bin.resolve()
    include_show_fixes = not args.no_show_fixes

    if not sql_dir.exists():
        raise FileNotFoundError(f"SQL directory not found: {sql_dir}")
    if not flowscope_bin.exists():
        raise FileNotFoundError(f"FlowScope binary not found: {flowscope_bin}")

    if args.mode == "batch":
        result = benchmark_batch(flowscope_bin, args.dialect, sql_dir, include_show_fixes)
        print(f"mode=batch elapsed_ms={result['elapsed_ms']:.3f}")
    else:
        result = benchmark_per_file(flowscope_bin, args.dialect, sql_dir, include_show_fixes)
        print(
            f"mode=per-file files={result['files']} total_ms={result['elapsed_ms']:.3f}"
        )
        for name, ms in result["rows"][:5]:
            print(f"top {name},{ms:.3f}")
        if args.csv_output:
            write_per_file_csv(result["rows"], args.csv_output)
            print(f"wrote_csv={args.csv_output}")

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        json_payload = {
            "sql_dir": str(sql_dir),
            "flowscope_bin": str(flowscope_bin),
            "dialect": args.dialect,
            "show_fixes": include_show_fixes,
            "result": {
                key: value
                for key, value in result.items()
                if key not in {"stderr", "rows"}
            },
        }
        args.json_output.write_text(json.dumps(json_payload, indent=2) + "\n")
        print(f"wrote_json={args.json_output}")


if __name__ == "__main__":
    main()
