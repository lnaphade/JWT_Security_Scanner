# Copyright (c) 2025 Your Name
# Licensed under the Educational Use License (EUL) OR Commercial License Agreement (CLA)
# See the root LICENSE (EUL) and COMMERCIAL_LICENSE files for full terms.
# If you obtained a commercial license, use constitutes acceptance of the CLA.
# Unauthorized commercial use is prohibited.

"""Idempotently apply license headers to project source files.

Usage:
    python apply_license_headers.py [--dry-run]

- Inserts header from LICENSE_HEADER_TEMPLATE.txt below an existing shebang
  or at file start if no shebang present.
- Ensures the shebang (if any) remains the very first line.
- Targets: *.py, *.sh (skips virtual envs, build, dist, .git, release)
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

HEADER_FILE = Path("LICENSE_HEADER_TEMPLATE.txt")
MARKER = "Licensed under the Educational Use License (EUL) OR Commercial License Agreement (CLA)"

EXCLUDE_DIRS = {".git", "dist", "build", "release", "__pycache__", ".venv"}
TARGET_EXT = {".py", ".sh"}


def should_process(path: Path) -> bool:
    if path.suffix not in TARGET_EXT:
        return False
    parts = set(p.name for p in path.parents)
    if parts & EXCLUDE_DIRS:
        return False
    return True


def apply_header(path: Path, header: str, dry_run: bool = False) -> bool:
    try:
        original = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"[WARN] Cannot read {path}: {e}")
        return False
    lines = original.splitlines()
    if lines:
        has_shebang = lines[0].startswith("#!/")
    else:
        has_shebang = False
    top_region = lines[:10]
    if any(MARKER in l for l in top_region):
        return False  # already has header
    # Construct new content
    if has_shebang:
        shebang = lines[0]
        body = "\n".join(lines[1:])
        new_content = shebang + "\n" + header + ("\n" if body and not body.startswith("\n") else "") + body
    else:
        new_content = header + ("\n" if original and not original.startswith("\n") else "") + original
    if not dry_run:
        path.write_text(new_content, encoding="utf-8")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Show files needing headers without modifying")
    args = parser.parse_args()

    if not HEADER_FILE.exists():
        print("[ERROR] Missing LICENSE_HEADER_TEMPLATE.txt")
        return 1
    header = HEADER_FILE.read_text(encoding="utf-8").rstrip() + "\n"

    changed = 0
    scanned = 0
    for path in Path(".").rglob("*"):
        if path.is_file() and should_process(path):
            scanned += 1
            if apply_header(path, header, dry_run=args.dry_run):
                changed += 1
                print(f"[ADD] {path}")
    print(f"Done. Scanned={scanned} Updated={changed}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
