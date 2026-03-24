# FURY0s1nt

Research, Detection, and Vulnerability Intelligence Platform.

FURY0s1nt is a source-available framework focused on:
- CVE intelligence and monitoring
- cryptographic auditing and quantum-readiness analysis
- integrity verification and reproducible reporting
- public-interest security research with safety constraints

The project prioritizes verifiable outputs, reviewable automation, and conservative default behavior over broad offensive capability claims.

## Trust Signals

- Code scanning with CodeQL in GitHub Actions
- OpenSSF Scorecard analysis in CI
- Workflow linting with actionlint
- SBOM generation and release provenance attestations
- Enforced secret scanning with reviewed baseline
- Integrity manifests with SHA-256 verification

## Core Platform Components

### CVE Intelligence
- `core/cve_engine.py`: NVD, CISA KEV, EPSS-backed lookup, enrichment, and reporting
- `core/cve_monitor.py`: watchlists, scheduled polling, and digest alerts

### Crypto and Audit
- `core/crypto_audit.py`: crypto weakness and migration analysis
- `core/quantum_crypto.py`: post-quantum and hybrid cryptographic workflows

### Integrity and Reporting
- `scripts/verify_integrity.py`: repository checksum generation and verification
- `data/cve/`: generated intelligence datasets and report outputs

## 60-Second Quickstart

```bash
pip install -r requirements.txt
python core/cve_engine.py sync --days 7 --kev
python core/cve_engine.py report --severity CRITICAL --days 7 --format json --output data/cve/critical_weekly.json
python scripts/demo_report.py --output data/cve/demo_report.json
python scripts/verify_integrity.py verify
```

## Demo Workflow

```bash
# 1) Refresh recent CVE + KEV data
python core/cve_engine.py sync --days 7 --kev

# 2) Produce a critical report pack
python core/cve_engine.py report --severity CRITICAL --days 7 --format json --output data/cve/critical_weekly.json
python core/cve_engine.py kev --recent 7 --format json --output data/cve/kev_recent.json

# 3) Verify repository integrity before sharing artifacts
python scripts/verify_integrity.py verify
```

## Safety and Scope

This repository is intended for authorized security research, detection engineering, and defensive analysis.

Sensitive areas (for example `payloads/`, `usb_payload/`, `firmware/`, `flipper/`, and `mobile/`) are treated as high-review paths and are subject to stricter PR governance in CI.

No warranty is provided for unauthorized use. See `LICENSE` and `SECURITY.md` for disclosure and legal terms.

## Reproducibility

- Use Actions-generated artifacts where available.
- Validate checksums from `CHECKSUMS.sha256`.
- Prefer release assets with attached provenance and SBOM evidence.
- Generate a local offline demo report with `python scripts/demo_report.py`.

## Engineering Artifacts

- Architecture: `docs/ARCHITECTURE.md`
- Governance: `docs/REPO_GOVERNANCE.md`
- Roadmap: `ROADMAP.md`
- Changelog: `CHANGELOG.md`
- Demo output path: `data/cve/demo_report.json`

## Maintainer Controls

- CODEOWNERS enforces default ownership for core and sensitive paths.
- Issue templates steer public contributions into docs, research, and safe contribution lanes.
- Branch protection should require CI, CodeQL, Scorecard, secret scanning, workflow linting, and sensitive-path review.

## Repository Layout

```text
core/               CVE intelligence, monitoring, auditing modules
data/cve/           Generated vulnerability intelligence outputs
scripts/            Integrity and utility scripts
.github/workflows/  Assurance, security, and governance automation
docs/               Platform docs and reference material
```

## Roadmap (Next 30 Days)

1. Harden branch protection and required status checks.
2. Publish a GitHub Pages CVE dashboard with sample reports.
3. Ship a versioned release with SBOM + attestation evidence.
4. Expand schema validation and test coverage for CVE/KEV outputs.
5. Add contributor-safe issues tagged `docs`, `research`, and `good first issue`.

## License

Source-available. See `LICENSE`.
