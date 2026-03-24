#!/usr/bin/env python3
"""Generate a local, reproducible demo CVE intelligence report.

This script intentionally reads repository-local CVE JSON records so contributors
can produce a sample report without network access or API keys.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class DemoRecord:
    cve_id: str
    severity: str
    score: Optional[float]
    cwe: str
    vendor: str
    product: str
    published: str
    title: str


def first_or_default(items: List[Any], default: Any = "") -> Any:
    return items[0] if items else default


def parse_record(path: Path) -> Optional[DemoRecord]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    meta = data.get("cveMetadata", {})
    cve_id = meta.get("cveId", path.stem)

    cna = data.get("containers", {}).get("cna", {})
    metrics = cna.get("metrics", [])

    severity = "UNKNOWN"
    score: Optional[float] = None

    for metric in metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss = metric.get(key)
            if cvss:
                severity = str(cvss.get("baseSeverity", "UNKNOWN")).upper()
                raw_score = cvss.get("baseScore")
                score = float(raw_score) if raw_score is not None else None
                break
        if score is not None or severity != "UNKNOWN":
            break

    cwe = "UNKNOWN"
    problem_types = cna.get("problemTypes", [])
    if problem_types:
        descriptions = first_or_default(problem_types, {}).get("descriptions", [])
        cwe = first_or_default(descriptions, {}).get("cweId", "UNKNOWN")

    affected = cna.get("affected", [])
    vendor = first_or_default(affected, {}).get("vendor", "UNKNOWN")
    product = first_or_default(affected, {}).get("product", "UNKNOWN")

    title = cna.get("title", "")
    published = meta.get("datePublished", "")

    return DemoRecord(
        cve_id=cve_id,
        severity=severity,
        score=score,
        cwe=cwe,
        vendor=vendor,
        product=product,
        published=published,
        title=title,
    )


def build_report(records: List[DemoRecord], top_n: int) -> Dict[str, Any]:
    records_sorted = sorted(
        records,
        key=lambda r: (r.score is not None, r.score if r.score is not None else -1.0),
        reverse=True,
    )

    severity_counts = Counter(r.severity for r in records_sorted)
    vendor_counts = Counter(r.vendor for r in records_sorted if r.vendor and r.vendor != "UNKNOWN")
    cwe_counts = Counter(r.cwe for r in records_sorted if r.cwe and r.cwe != "UNKNOWN")

    top_critical = [
        {
            "cve_id": r.cve_id,
            "score": r.score,
            "severity": r.severity,
            "vendor": r.vendor,
            "product": r.product,
            "cwe": r.cwe,
            "published": r.published,
            "title": r.title,
        }
        for r in records_sorted
        if r.severity == "CRITICAL"
    ][:top_n]

    top_by_score = [
        {
            "cve_id": r.cve_id,
            "score": r.score,
            "severity": r.severity,
            "vendor": r.vendor,
            "product": r.product,
            "cwe": r.cwe,
            "published": r.published,
            "title": r.title,
        }
        for r in records_sorted[:top_n]
    ]

    generated_at = datetime.now(timezone.utc).isoformat()

    return {
        "meta": {
            "report_type": "local_demo_cve_intelligence",
            "generated_at": generated_at,
            "record_count": len(records_sorted),
        },
        "summary": {
            "severity_counts": dict(severity_counts),
            "top_vendors": [{"vendor": k, "count": v} for k, v in vendor_counts.most_common(top_n)],
            "top_cwes": [{"cwe": k, "count": v} for k, v in cwe_counts.most_common(top_n)],
        },
        "highlights": {
            "top_critical": top_critical,
            "top_by_score": top_by_score,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a local demo CVE report from repository JSON files")
    parser.add_argument("--input-glob", default="CVE-*.json", help="Glob pattern for CVE JSON files")
    parser.add_argument("--output", default="data/cve/demo_report.json", help="Output report path")
    parser.add_argument("--top", type=int, default=10, help="Number of top entries to include")
    args = parser.parse_args()

    files = sorted(Path(".").glob(args.input_glob))
    if not files:
        print("No CVE JSON files found for demo report generation.")
        return 1

    records: List[DemoRecord] = []
    for file_path in files:
        record = parse_record(file_path)
        if record is not None:
            records.append(record)

    if not records:
        print("No parseable CVE records found.")
        return 1

    report = build_report(records, max(args.top, 1))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Generated demo report: {out_path}")
    print(f"Records analyzed: {report['meta']['record_count']}")
    print(f"Top severity buckets: {report['summary']['severity_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
