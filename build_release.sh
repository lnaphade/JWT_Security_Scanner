#!/usr/bin/env bash
set -euo pipefail

# Production Release Build Script for jwt_tool
# Usage: ./build_release.sh [version]
# Optional env vars:
#   PYTHON_BIN=python3
#   SKIP_PYINSTALLER=1 (skip binary builds)
#   SKIP_SBOM=1 (skip SBOM generation)

VERSION="${1:-2.0.0}"
PROJECT="jwt_tool"
OUTDIR="release/${VERSION}"
DATE_UTC="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
GIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo 'nogit')"
PYTHON_BIN="${PYTHON_BIN:-python3}"

banner() { echo -e "\n==== $* ===="; }

banner "Preparing build directories"
rm -rf dist build "${OUTDIR}" || true
mkdir -p "${OUTDIR}/artifacts" "${OUTDIR}/binaries" "${OUTDIR}/source"

banner "Writing build metadata"
cat > BUILD_METADATA.txt <<EOF
Project: ${PROJECT}
Version: ${VERSION}
Build Timestamp (UTC): ${DATE_UTC}
Git Commit: ${GIT_HASH}
Builder Host: $(uname -a)
Python: $(${PYTHON_BIN} --version 2>&1)
EOF

banner "Creating virtual environment"
${PYTHON_BIN} -m venv .buildenv
source .buildenv/bin/activate
python -m pip install --upgrade pip >/dev/null

banner "Installing dependencies"
pip install -r requirements.txt >/dev/null
pip install build pyinstaller cyclonedx-bom >/dev/null 2>&1 || true

banner "Running smoke import test"
python - <<'PY'
for m in ("jwt_tool", "jwt_tool_standalone"):
    __import__(m)
print("Imports OK")
PY

banner "Building source distribution (wheel+sdist)"
python -m build --sdist --wheel >/dev/null || echo "[WARN] build module failed"
cp dist/*.tar.gz dist/*.whl "${OUTDIR}/artifacts/" 2>/dev/null || true

if [[ -z "${SKIP_SBOM:-}" ]]; then
  banner "Generating SBOM (CycloneDX)"
  cyclonedx-bom -o "${OUTDIR}/artifacts/sbom.json" -e requirements.txt >/dev/null 2>&1 || echo "[WARN] SBOM generation skipped"
fi

if [[ -z "${SKIP_PYINSTALLER:-}" ]]; then
  banner "Building PyInstaller CLI binary"
  pyinstaller --onefile --name jwt_tool_cli jwt_tool.py >/dev/null 2>&1 || echo "[WARN] CLI build failed"
  banner "Building PyInstaller GUI binary"
  pyinstaller --onefile --windowed --name jwt_tool_gui jwt_tool_standalone.py >/dev/null 2>&1 || echo "[WARN] GUI build failed"
  cp dist/jwt_tool_cli* "${OUTDIR}/binaries/" 2>/dev/null || true
  cp dist/jwt_tool_gui* "${OUTDIR}/binaries/" 2>/dev/null || true
fi

banner "Collecting source package"
cp jwt_tool.py jwt_tool_standalone.py requirements.txt README.md BUILD_METADATA.txt \
   jwt_security_analyzer.py comprehensive_jwt_security_report.html jwt_security_report.html \
   "${OUTDIR}/source/" 2>/dev/null || true

# Restore data files if present (some may have been removed earlier)
for f in common-headers.txt common-payloads.txt jwt-common.txt jwks-common.txt; do
  [[ -f "$f" ]] && cp "$f" "${OUTDIR}/source/" || echo "[INFO] Missing optional data file: $f"
done

banner "Writing quick test script"
cat > "${OUTDIR}/source/quicktest.py" <<'QPY'
import base64
from datetime import datetime

print("Quick JWT decode test:")
header="eyJhbGciOiJFUzI1NiJ9"
payload="eyJ0ZXN0Ijoiand0IiwiaWF0IjoxNjAwMDAwMDAwfQ"
for part,label in ((header,'header'), (payload,'payload')):
    data = base64.urlsafe_b64decode(part + '==')
    print(label+':', data)
print('OK')
QPY

banner "Generating checksums"
(
  cd "release/${VERSION}" || exit 1
  find . -type f ! -name checksums.txt -print0 | sort -z | while IFS= read -r -d '' f; do
    shasum -a 256 "$f"
  done > checksums.txt
)

banner "Creating archive bundles"
(
  cd release || exit 1
  tar -czf "${PROJECT}_${VERSION}_full.tar.gz" "${VERSION}" || true
  zip -rq "${PROJECT}_${VERSION}_full.zip" "${VERSION}" || true
)

banner "Build complete"
echo "Artifacts:"
ls -1 "release/${PROJECT}_${VERSION}_full."* 2>/dev/null || true
