# FURY0s1nt Roadmap

## v5.0 Focus: Verified Vulnerability Intelligence

### Track A: Trust and Assurance
- Require CodeQL, secret-scan, CI, and Scorecard as branch protection checks
- Pin action versions by commit SHA for critical workflows
- Expand release attestations to all published report bundles
- Add scheduled validation of workflow permissions drift

### Track B: Data Quality
- Add JSON schema validation for generated CVE/KEV report outputs
- Add regression fixtures for parser edge cases (missing metrics, malformed CVE metadata)
- Add confidence tags and source provenance metadata to report records

### Track C: Product Experience
- Publish a GitHub Pages dashboard for CVE trend snapshots
- Add screenshot-backed demo walkthrough in docs
- Add one-command demo target with generated report pack

### Track D: Governance and Safety
- Add CODEOWNERS for sensitive directories
- Enforce safety checklist completion on sensitive-path PRs
- Add issue templates for docs/research/safe-contrib requests

## Delivery Milestones

1. Milestone 1 (Foundation): branch protection + required checks + Codeowners
2. Milestone 2 (Evidence): schema validation + fixture tests + expanded release evidence
3. Milestone 3 (Experience): dashboard + screenshots + demo kit
4. Milestone 4 (Community): contributor-safe issue taxonomy and public project board
