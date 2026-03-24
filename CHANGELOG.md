# Changelog

## [Unreleased]

### Added
- CodeQL workflow for Python and JavaScript analysis
- OpenSSF Scorecard workflow with SARIF upload
- actionlint workflow for GitHub Actions linting
- Release provenance workflow with SBOM generation and artifact attestations
- Sensitive-path review workflow for elevated PR governance
- Pull request template with required safety checklist
- Local demo report generator: scripts/demo_report.py
- Architecture overview document: docs/ARCHITECTURE.md
- Public roadmap document: ROADMAP.md

### Changed
- Hardened CI and automation workflows with timeout and concurrency controls
- Strengthened dependency audit to produce artifacts and SBOM evidence
- Reworked secret scanning to enforce baseline-diff findings
- Repositioned README toward research-grade CVE intelligence and trust signals

### Security
- Repository security signals now include CodeQL, Scorecard, and stricter secret scanning policy
- Release process now includes provenance-focused evidence artifacts
