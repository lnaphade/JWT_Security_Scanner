# JWT Tool: Advanced JWT Security Testing Suite

![jwt_tool version](https://img.shields.io/badge/version-v2.0.0-blue) ![python version](https://img.shields.io/badge/python-v3.8+-green) ![GUI Support](https://img.shields.io/badge/GUI-enabled-brightgreen)

**Version 2.0.0 (01 August 2025)**

A comprehensive, streamlined JWT (JSON Web Token) security testing toolkit with both CLI and GUI interfaces. This tool provides complete JWT analysis, manipulation, and vulnerability testing capabilities in a clean, efficient codebase.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip package manager

### Installation
```bash
git clone https://github.com/yourusername/jwt_tool.git
cd jwt_tool
pip install -r requirements.txt
```

### Usage Options

#### Option 1: GUI Interface (Recommended)
```bash
python3 jwt_tool_standalone.py
```
The GUI provides an intuitive interface with tabs for all JWT operations.

#### Option 2: CLI Interface (Advanced Users)
```bash
python3 jwt_tool.py [options] <JWT>
```
Full-featured command-line interface for automation and advanced users.

## 📁 Project Structure (Core Files)
```
jwt_tool/
├── jwt_tool.py              # Full-featured CLI tool (main file)
├── jwt_tool_standalone.py   # GUI application
├── jwt_security_analyzer.py # Advanced security analysis engine
├── comprehensive_jwt_security_report.html # Detailed HTML security report
├── jwt_security_report.html # Basic HTML security report
├── analyze_token.py         # Lightweight claim analysis helper
├── requirements.txt         # Runtime dependencies
├── requirements.lock        # Frozen dependency versions (reproducible builds)
├── build_release.sh         # Release automation script
├── smoke_test.py            # Sanity test script
├── CHANGELOG.md             # Release history
├── SECURITY_NOTICE.md       # Responsible usage & disclosure
├── common-headers.txt       # Common header names
├── common-payloads.txt      # Common payload claim names
├── jwt-common.txt           # Common secrets list
├── jwks-common.txt          # Sample JWKS items
└── README.md
```

## 🔧 Features
(Condensed; full details later in this document)
- Decode / Verify / Sign / Edit / Crack / Exploit / Scan
- Supports HS*, RS*, PS*, and ES* (ES256/384/512) algorithms
- Advanced analyzer with vulnerability matrix and CVSS-style scoring
- HTML reporting (basic + comprehensive)
- Dictionary-based cracking & attack simulation

## 🛡️ Security Testing Capabilities
Key vulnerability checks include: algorithm confusion, alg=none, key injection (jku/jwk), weak secrets, null signature, ECDSA psychic signature concerns, timestamp manipulation, and claim tampering.

## 💻 Usage Examples
```bash
# Decode a JWT
python3 jwt_tool.py <JWT>

# Crack a JWT signature
python3 jwt_tool.py -C -d jwt-common.txt <JWT>

# Sign a new JWT
python3 jwt_tool.py -S hs256 -p "secret" <HEADER.PAYLOAD>

# Run vulnerability scan (pb mode)
python3 jwt_tool.py -M pb <JWT>

# Advanced security analysis
python3 jwt_security_analyzer.py
```

## 🧪 Smoke Test
Run a quick sanity check:
```bash
python3 smoke_test.py
```
Expect imports to succeed and CLI help to print.

## 📦 Release & Build
This project includes automated release tooling.

### Local Production Build
```bash
chmod +x build_release.sh
./build_release.sh 2.0.0
```
Outputs:
- release/2.0.0/ (binaries, artifacts, source)
- Checksums (SHA256) and SBOM (CycloneDX) if dependencies present
- Compressed archives: jwt_tool_2.0.0_full.(tar.gz|zip)

Optional flags:
- SKIP_PYINSTALLER=1 to skip binary builds
- SKIP_SBOM=1 to skip SBOM generation
- PYTHON_BIN=python3.11 to select Python

Example:
```bash
SKIP_SBOM=1 ./build_release.sh 2.0.0
```

### GitHub Actions Release
A workflow (`.github/workflows/release.yml`) triggers on tag push (v*). To create a release:
```bash
git tag v2.0.0
git push origin v2.0.0
```
Artifacts uploaded: wheel, sdist, (optional) PyInstaller binaries, SBOM, checksums, CHANGELOG, SECURITY_NOTICE.

### Verifying Artifacts
```bash
shasum -a 256 -c release/2.0.0/checksums.txt | grep OK
```

## 🔒 Responsible Usage
Use only with explicit authorization. See `SECURITY_NOTICE.md` for guidelines and disclosure process.

## 📚 Dependencies
Core dependencies listed in `requirements.txt`. Reproducible versions pinned in `requirements.lock`.

## 🐛 Troubleshooting (Common)
1. PyQt5 Import Error -> pip install PyQt5
2. ES256 errors -> ensure pycryptodomex installed
3. GUI fails on headless -> use CLI or set up virtual display
4. Permission denied -> chmod +x build_release.sh

## 👤 Author
Your Name
- Website: https://cosmoslab.in
- GitHub: https://github.com/lnaphade/jwt_tool
- Email: lnaphade@gmail.com

## 🙏 Acknowledgments
Thanks to the security research community and library maintainers.

---
Use responsibly and only on systems you're authorized to test!
