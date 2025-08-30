"""Simple smoke tests for jwt_tool project.
Run: python smoke_test.py
"""
import importlib
import subprocess
import sys
from pathlib import Path

MODULES = ["jwt_tool", "jwt_tool_standalone", "jwt_security_analyzer"]


def check_imports():
    print("[SMOKE] Importing modules...")
    for m in MODULES:
        try:
            importlib.import_module(m)
            print(f"  OK: {m}")
        except Exception as e:
            print(f"  FAIL: {m} -> {e}")
            return False
    return True

def check_cli_help():
    print("[SMOKE] Checking CLI help output...")
    try:
        out = subprocess.check_output([sys.executable, "jwt_tool.py", "-h"], stderr=subprocess.STDOUT, timeout=10).decode()
        if "Usage" in out or "usage" in out:
            print("  OK: help displayed")
            return True
        print("  WARN: help output did not contain expected text")
        return False
    except Exception as e:
        print(f"  FAIL: invoking help -> {e}")
        return False

def main():
    root = Path(__file__).parent
    print("[SMOKE] Project root:", root)
    ok = True
    ok &= check_imports()
    ok &= check_cli_help()
    if ok:
        print("[SMOKE] SUCCESS: basic sanity checks passed")
        sys.exit(0)
    else:
        print("[SMOKE] FAILURE: one or more checks failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
