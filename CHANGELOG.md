# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2025-08-30
### Added
- ES256 / ES384 / ES512 (ECDSA) algorithm support.
- Advanced security analyzer script (`jwt_security_analyzer.py`) with algorithm assessment, claims validation, and vulnerability matrix output.
- Comprehensive HTML security report (`comprehensive_jwt_security_report.html`) with risk descriptions, impacts, mitigations, CVSS-style scoring, and recommendations.
- Initial HTML scan report (`jwt_security_report.html`).
- `analyze_token.py` lightweight claims inspection helper.
- Production build script (`build_release.sh`) generating wheels, PyInstaller binaries, SBOM, checksums, and archives.
- Smoke test script (`smoke_test.py`) for quick sanity verification.

### Changed
- Rebranded project (removed previous author references, updated banner and README author/contact info).
- Updated README with new features and usage examples.

### Removed
- Original LICENSE reference (project distributed without previous license metadata pending new licensing decision).

### Security
- Added explicit warnings for missing critical claims (exp, jti, kid) and algorithm downgrade risks.

[2.0.0]: https://example.com/releases/2.0.0 (placeholder)
