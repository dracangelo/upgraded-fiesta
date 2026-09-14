#!/usr/bin/env python3
"""Evaluate the synthetic pipeline benchmark against scale-aware ceilings."""

from __future__ import annotations

import json
import pathlib
import re
import sys

BENCHMARK = re.compile(
    r"^BenchmarkLargeScaleEventPipeline-\d+\s+\d+\s+(\d+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op$",
    re.MULTILINE,
)


def evaluate(text: str, targets: int) -> dict[str, int | bool]:
    match = BENCHMARK.search(text)
    if not match:
        raise ValueError("pipeline benchmark result was not found")
    nanoseconds, bytes_per_op, allocations = map(int, match.groups())
    ceilings = {
        "nanoseconds": 2_000_000_000 + targets * 5_000_000,
        "bytes_per_op": 10_000_000 + targets * 65_536,
        "allocations": 10_000 + targets * 500,
    }
    passed = (
        nanoseconds <= ceilings["nanoseconds"]
        and bytes_per_op <= ceilings["bytes_per_op"]
        and allocations <= ceilings["allocations"]
    )
    return {
        "targets": targets,
        "nanoseconds": nanoseconds,
        "bytes_per_op": bytes_per_op,
        "allocations": allocations,
        "max_nanoseconds": ceilings["nanoseconds"],
        "max_bytes_per_op": ceilings["bytes_per_op"],
        "max_allocations": ceilings["allocations"],
        "passed": passed,
    }


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: evaluate_field_validation.py <benchmark.txt> <targets> <summary.json>", file=sys.stderr)
        return 2
    benchmark, targets, output = pathlib.Path(sys.argv[1]), int(sys.argv[2]), pathlib.Path(sys.argv[3])
    result = evaluate(benchmark.read_text(), targets)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not result["passed"]:
        print(json.dumps(result, indent=2), file=sys.stderr)
        return 1
    print(f"field-validation thresholds passed for {targets} targets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

