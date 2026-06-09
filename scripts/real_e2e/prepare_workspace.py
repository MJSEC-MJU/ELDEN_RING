from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare the live target-app workspace for real E2E remediation.")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--reset", action="store_true", help="Replace the live workspace with a fresh vulnerable copy")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    source = root / "services" / "target-app"
    workspace = root / "runtime" / "live-workspace" / "services" / "target-app"

    if not source.exists():
        raise SystemExit(f"source target-app not found: {source}")
    if args.reset and workspace.exists():
        shutil.rmtree(workspace)
    workspace.parent.mkdir(parents=True, exist_ok=True)
    if not workspace.exists():
        shutil.copytree(
            source,
            workspace,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
        )
    print(f"live workspace ready: {workspace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
