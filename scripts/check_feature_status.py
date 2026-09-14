#!/usr/bin/env python3
"""Fail when roadmap declarations contradict the code-owned manifest."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DECLARATION = re.compile(r"<!--\s*capability:([a-z0-9-]+)=([a-z_]+)\s*-->")
VALID = {"implemented", "experimental", "gated", "planned", "intentionally_excluded"}


def render(fmt: str) -> str:
    return subprocess.run(
        ["go", "run", "./cmd/enumscan", "capabilities", "-format", fmt],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> int:
    manifest = json.loads(render("json"))
    actual = {item["id"]: item["status"] for item in manifest["capabilities"]}
    declarations = DECLARATION.findall((ROOT / "ROADMAP.md").read_text())
    errors: list[str] = []
    seen: set[str] = set()
    for capability_id, declared_status in declarations:
        if capability_id in seen:
            errors.append(f"duplicate ROADMAP declaration for {capability_id}")
        seen.add(capability_id)
        if declared_status not in VALID:
            errors.append(f"invalid status {declared_status!r} for {capability_id}")
        elif capability_id not in actual:
            errors.append(f"unknown capability in ROADMAP: {capability_id}")
        elif actual[capability_id] != declared_status:
            errors.append(
                f"{capability_id}: ROADMAP={declared_status}, manifest={actual[capability_id]}"
            )
    if not declarations:
        errors.append("ROADMAP.md has no machine-readable capability declarations")
    generated = ROOT / "docs" / "capabilities.md"
    if not generated.exists() or generated.read_text() != render("markdown"):
        errors.append("docs/capabilities.md is stale; run make docs")
    if errors:
        print("feature status check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"feature status check passed ({len(actual)} capabilities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

