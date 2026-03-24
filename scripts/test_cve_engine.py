#!/usr/bin/env python3
"""
Regression tests for CVE engine fixes:
  1. FTS5 UPSERT crash (OperationalError: UPSERT not implemented for virtual table)
  2. kev --output argument (clean JSON output without status-message corruption)
  3. DB schema init, upsert_cve, upsert_kev, FTS rebuild
"""
import json
import os
import sys
import tempfile

# Allow running from repo root or scripts/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cve_engine
from cve_engine import (
    CVEDatabase,
    CVERecord,
    CVSSMetrics,
    CVEReporter,
    KEVEntry,
    _build_parser,
    _kev_to_enriched,
    _write_output,
)


def _tmpdb() -> CVEDatabase:
    tmpdir = tempfile.mkdtemp()
    return CVEDatabase(os.path.join(tmpdir, "test.db"))


def test_upsert_cve_no_fts5_error():
    """upsert_cve must not raise OperationalError on FTS5 virtual table."""
    db = _tmpdb()
    rec = CVERecord(
        cve_id="CVE-2024-0001",
        description="Test RCE in Apache",
        cvss=CVSSMetrics(score=9.8, severity="CRITICAL", vector="CVSS:3.1/AV:N", version="3.1"),
        published="2024-01-01",
        modified="2024-01-02",
    )
    db.upsert_cve(rec)
    db.close()
    print("  PASS: upsert_cve — no FTS5 OperationalError")


def test_upsert_cve_idempotent():
    """upsert_cve must be idempotent (no error on second call with same cve_id)."""
    db = _tmpdb()
    rec = CVERecord(
        cve_id="CVE-2024-0002",
        description="First description",
        cvss=CVSSMetrics(score=7.5, severity="HIGH", vector="CVSS:3.1/AV:N", version="3.1"),
        published="2024-01-01",
        modified="2024-01-02",
    )
    db.upsert_cve(rec)
    rec.description = "Updated description"
    db.upsert_cve(rec)
    row = db.conn.execute("SELECT description FROM cves WHERE cve_id = ?", ("CVE-2024-0002",)).fetchone()
    assert row["description"] == "Updated description", f"Expected updated description, got: {row['description']}"
    db.close()
    print("  PASS: upsert_cve — idempotent update works")


def test_fts5_rebuild():
    """FTS5 content='' table can be rebuilt with: INSERT INTO cve_fts(cve_fts) VALUES('rebuild')"""
    db = _tmpdb()
    rec = CVERecord(
        cve_id="CVE-2024-0003",
        description="Apache Log4j JNDI RCE",
        cvss=CVSSMetrics(score=10.0, severity="CRITICAL", vector="CVSS:3.1/AV:N", version="3.1"),
        published="2024-01-01",
        modified="2024-01-02",
    )
    db.upsert_cve(rec)
    db.conn.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
    db.conn.commit()
    db.close()
    print("  PASS: FTS5 rebuild — no OperationalError")


def test_upsert_kev():
    """upsert_kev must succeed and be idempotent."""
    db = _tmpdb()
    entry = KEVEntry(
        cve_id="CVE-2022-26134",
        vendor="Atlassian",
        product="Confluence",
        name="Atlassian Confluence OGNL Injection",
        description="OGNL injection allowing unauthenticated RCE",
        date_added="2022-06-03",
        due_date="2022-06-17",
        known_ransomware="Known",
    )
    db.upsert_kev(entry)
    entry.known_ransomware = "Updated"
    db.upsert_kev(entry)
    row = db.conn.execute("SELECT known_ransomware FROM kev WHERE cve_id = ?", ("CVE-2022-26134",)).fetchone()
    assert row["known_ransomware"] == "Updated", f"Expected 'Updated', got: {row['known_ransomware']}"
    db.close()
    print("  PASS: upsert_kev — idempotent update works")


def test_kev_output_argument():
    """kev subcommand must have --output argument in its arg parser."""
    p = _build_parser()
    args = p.parse_args(["kev", "--recent", "7", "--format", "json", "--output", "/tmp/kev_test.json"])
    assert args.recent == 7
    assert args.format == "json"
    assert args.output == "/tmp/kev_test.json"
    print("  PASS: kev --output argument is registered in the parser")


def test_kev_output_clean_json():
    """kev --output must write valid JSON without status-message contamination."""
    tmpfile = os.path.join(tempfile.mkdtemp(), "kev_output.json")
    reporter = CVEReporter()
    entries = [
        KEVEntry(
            cve_id="CVE-2023-44487",
            vendor="Multiple",
            product="HTTP/2",
            name="HTTP/2 Rapid Reset Attack",
            description="HTTP/2 Rapid Reset allows DDoS amplification",
            date_added="2023-10-10",
            due_date="2023-10-31",
            known_ransomware="Unknown",
        )
    ]
    enriched = _kev_to_enriched(entries)
    _write_output(reporter.to_json(enriched), tmpfile)

    with open(tmpfile) as f:
        content = f.read()

    data = json.loads(content)
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2023-44487"
    print("  PASS: kev --output writes clean JSON (no status-message contamination)")


def test_write_output_to_file():
    """_write_output must write content to file when path is provided."""
    tmpfile = os.path.join(tempfile.mkdtemp(), "out.json")
    _write_output('{"test": true}', tmpfile)
    with open(tmpfile) as f:
        data = json.load(f)
    assert data["test"] is True
    print("  PASS: _write_output — writes content to file path")


def run_all():
    tests = [
        test_upsert_cve_no_fts5_error,
        test_upsert_cve_idempotent,
        test_fts5_rebuild,
        test_upsert_kev,
        test_kev_output_argument,
        test_kev_output_clean_json,
        test_write_output_to_file,
    ]
    print(f"Running {len(tests)} CVE engine regression tests...\n")
    failed = []
    for test in tests:
        try:
            test()
        except Exception as exc:
            print(f"  FAIL: {test.__name__} -> {exc}")
            failed.append(test.__name__)

    print()
    if failed:
        print(f"FAILED: {len(failed)}/{len(tests)} tests failed: {failed}")
        sys.exit(1)
    else:
        print(f"All {len(tests)} tests passed.")


if __name__ == "__main__":
    run_all()
