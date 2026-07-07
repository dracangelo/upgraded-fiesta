#!/usr/bin/env python3
"""Print a compact summary from an enumscan JSON report."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize_report.py reports/<scan-id>.json", file=sys.stderr)
        return 2

    data = json.loads(Path(sys.argv[1]).read_text())
    assets = data.get("assets", [])
    findings = data.get("findings", [])
    asset_counts = Counter(asset.get("Type") or asset.get("type") for asset in assets)
    finding_counts = Counter(finding.get("severity", "unknown") for finding in findings)

    print(f"scan_id: {data.get('scan_id')}")
    print(f"assets: {len(assets)}")
    for kind, count in sorted(asset_counts.items()):
        print(f"  {kind}: {count}")
    print(f"findings: {len(findings)}")
    for severity, count in sorted(finding_counts.items()):
        print(f"  {severity}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

