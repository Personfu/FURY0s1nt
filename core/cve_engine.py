#!/usr/bin/env python3
"""
===============================================================================
  FU PERSON :: CVE INTELLIGENCE ENGINE v1.0
  NVD Lookup | CISA KEV | EPSS Scoring | Exploit-DB Cross-Reference
  Local SQLite Cache | Risk Analysis | Enriched Reporting
===============================================================================

  AUTHORIZATION REQUIRED - DO NOT USE WITHOUT WRITTEN PERMISSION

  LEGAL NOTICE:
  This tool queries publicly available vulnerability databases.
  Ensure you comply with NVD, CISA, and Exploit-DB terms of service.
  Only use intelligence gathered for:
    1. Defensive security operations
    2. Authorized vulnerability management programs
    3. Permitted research within your scope of engagement

  FLLC
  Government-Cleared Security Operations
===============================================================================
"""

import os
import sys
import re
import json
import time
import sqlite3
import argparse
import hashlib
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any, Set
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
    from requests.exceptions import RequestException, Timeout
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


# =============================================================================
#  ANSI COLORS & DISPLAY
# =============================================================================

class C:
    R   = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"

    @staticmethod
    def p(text: str):
        try:
            print(text)
        except UnicodeEncodeError:
            print(re.sub(r"\033\[[0-9;]*m", "", str(text)))

    @staticmethod
    def ok(msg: str):
        C.p(f"  {C.GRN}[+]{C.R} {msg}")

    @staticmethod
    def info(msg: str):
        C.p(f"  {C.BLU}[*]{C.R} {msg}")

    @staticmethod
    def warn(msg: str):
        C.p(f"  {C.YLW}[!]{C.R} {msg}")

    @staticmethod
    def fail(msg: str):
        C.p(f"  {C.RED}[-]{C.R} {msg}")

    @staticmethod
    def banner(title: str):
        w = 70
        C.p(f"\n  {C.CYN}{'=' * w}")
        C.p(f"  {C.BLD}{C.WHT}  {title}")
        C.p(f"  {C.CYN}{'=' * w}{C.R}\n")


# =============================================================================
#  DATA STRUCTURES
# =============================================================================

@dataclass
class CVSSMetrics:
    score: float = 0.0
    vector: str = ""
    severity: str = "UNKNOWN"
    version: str = "3.1"


@dataclass
class CVERecord:
    cve_id: str = ""
    description: str = ""
    cvss: CVSSMetrics = field(default_factory=CVSSMetrics)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cpe_matches: List[str] = field(default_factory=list)
    published: str = ""
    modified: str = ""


@dataclass
class KEVEntry:
    cve_id: str = ""
    vendor: str = ""
    product: str = ""
    name: str = ""
    description: str = ""
    date_added: str = ""
    due_date: str = ""
    known_ransomware: str = "Unknown"


@dataclass
class EPSSScore:
    cve_id: str = ""
    probability: float = 0.0
    percentile: float = 0.0
    date: str = ""


@dataclass
class ExploitRef:
    edb_id: str = ""
    title: str = ""
    platform: str = ""
    exploit_type: str = ""
    language: str = ""
    cve_id: str = ""


@dataclass
class EnrichedCVE:
    cve_id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = "UNKNOWN"
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    epss_probability: float = 0.0
    epss_percentile: float = 0.0
    in_kev: bool = False
    kev_due_date: str = ""
    known_ransomware: str = "Unknown"
    exploit_available: bool = False
    exploit_count: int = 0
    risk_score: float = 0.0
    published_date: str = ""
    modified_date: str = ""


# =============================================================================
#  NVD API v2 CLIENT
# =============================================================================

class NVDClient:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None):
        if not HAS_REQUESTS:
            raise RuntimeError("requests library required: pip install requests")
        self.api_key: Optional[str] = api_key or os.environ.get("NVD_API_KEY")
        self.session: requests.Session = requests.Session()
        self.session.headers.update({"User-Agent": "FU-PERSON-CVE-Engine/1.0"})
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        self._rate_limit = 50 if self.api_key else 6
        self._request_times: List[float] = []

    def _throttle(self) -> None:
        now = time.monotonic()
        window = 60.0
        self._request_times = [t for t in self._request_times if now - t < window]
        if len(self._request_times) >= self._rate_limit:
            sleep_for = window - (now - self._request_times[0]) + 0.5
            if sleep_for > 0:
                C.info(f"Rate limit reached, sleeping {sleep_for:.1f}s ...")
                time.sleep(sleep_for)
        self._request_times.append(time.monotonic())

    def _get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        self._throttle()
        try:
            resp = self.session.get(self.BASE_URL, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except Timeout:
            C.fail("NVD API request timed out")
            return {}
        except RequestException as exc:
            C.fail(f"NVD API error: {exc}")
            return {}

    def _paginate(self, params: Dict[str, Any], max_results: int = 2000) -> List[Dict]:
        results: List[Dict] = []
        params["resultsPerPage"] = min(max_results, 2000)
        params["startIndex"] = 0
        while True:
            data = self._get(params)
            if not data:
                break
            vulns = data.get("vulnerabilities", [])
            results.extend(vulns)
            total = data.get("totalResults", 0)
            fetched = params["startIndex"] + len(vulns)
            if fetched >= total or fetched >= max_results or not vulns:
                break
            params["startIndex"] = fetched
        return results

    @staticmethod
    def _parse_cve(vuln_wrapper: Dict) -> CVERecord:
        cve_data = vuln_wrapper.get("cve", {})
        rec = CVERecord()
        rec.cve_id = cve_data.get("id", "")
        rec.published = cve_data.get("published", "")
        rec.modified = cve_data.get("lastModified", "")

        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                rec.description = desc.get("value", "")
                break

        metrics = cve_data.get("metrics", {})
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                primary = metric_list[0]
                cvss_data = primary.get("cvssData", {})
                rec.cvss = CVSSMetrics(
                    score=cvss_data.get("baseScore", 0.0),
                    vector=cvss_data.get("vectorString", ""),
                    severity=cvss_data.get("baseSeverity",
                                           primary.get("baseSeverity", "UNKNOWN")).upper(),
                    version=cvss_data.get("version", version_key[-2:]),
                )
                break

        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    rec.cwe_ids.append(val)

        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            if url:
                rec.references.append(url)

        for config_node in cve_data.get("configurations", []):
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        rec.cpe_matches.append(cpe)
        return rec

    def search_cve(self, cve_id: str) -> Optional[CVERecord]:
        cve_id = cve_id.upper().strip()
        data = self._get({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if vulns:
            return self._parse_cve(vulns[0])
        return None

    def search_keyword(self, keyword: str, start_date: Optional[str] = None,
                       end_date: Optional[str] = None,
                       max_results: int = 200) -> List[CVERecord]:
        params: Dict[str, Any] = {"keywordSearch": keyword}
        if start_date:
            params["pubStartDate"] = self._iso_date(start_date)
        if end_date:
            params["pubEndDate"] = self._iso_date(end_date)
        vulns = self._paginate(params, max_results)
        return [self._parse_cve(v) for v in vulns]

    def search_product(self, cpe_name: str,
                       max_results: int = 200) -> List[CVERecord]:
        params: Dict[str, Any] = {"cpeName": cpe_name}
        vulns = self._paginate(params, max_results)
        return [self._parse_cve(v) for v in vulns]

    def search_severity(self, severity: str, start_date: Optional[str] = None,
                        max_results: int = 200) -> List[CVERecord]:
        severity = severity.upper().strip()
        params: Dict[str, Any] = {"cvssV3Severity": severity}
        if start_date:
            params["pubStartDate"] = self._iso_date(start_date)
        else:
            week_ago = datetime.now(timezone.utc) - timedelta(days=30)
            params["pubStartDate"] = week_ago.strftime("%Y-%m-%dT%H:%M:%S.000")
        vulns = self._paginate(params, max_results)
        return [self._parse_cve(v) for v in vulns]

    @staticmethod
    def _iso_date(date_str: str) -> str:
        date_str = date_str.strip()
        if "T" not in date_str:
            date_str += "T00:00:00.000"
        return date_str


# =============================================================================
#  CISA KNOWN EXPLOITED VULNERABILITIES CLIENT
# =============================================================================

class CISAKEVClient:

    CATALOG_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                   "known_exploited_vulnerabilities.json")

    def __init__(self):
        if not HAS_REQUESTS:
            raise RuntimeError("requests library required: pip install requests")
        self.session: requests.Session = requests.Session()
        self.session.headers.update({"User-Agent": "FU-PERSON-CVE-Engine/1.0"})
        self._catalog: List[KEVEntry] = []
        self._catalog_ts: float = 0.0

    def fetch_catalog(self, force: bool = False) -> List[KEVEntry]:
        if self._catalog and not force and (time.time() - self._catalog_ts < 3600):
            return self._catalog
        try:
            resp = self.session.get(self.CATALOG_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except RequestException as exc:
            C.fail(f"CISA KEV fetch error: {exc}")
            return self._catalog

        entries: List[KEVEntry] = []
        for v in data.get("vulnerabilities", []):
            entry = KEVEntry(
                cve_id=v.get("cveID", ""),
                vendor=v.get("vendorProject", ""),
                product=v.get("product", ""),
                name=v.get("vulnerabilityName", ""),
                description=v.get("shortDescription", ""),
                date_added=v.get("dateAdded", ""),
                due_date=v.get("dueDate", ""),
                known_ransomware=v.get("knownRansomwareCampaignUse", "Unknown"),
            )
            entries.append(entry)
        self._catalog = entries
        self._catalog_ts = time.time()
        C.ok(f"Loaded {len(entries)} KEV entries from CISA catalog")
        return entries

    def search(self, keyword: str) -> List[KEVEntry]:
        catalog = self.fetch_catalog()
        kw = keyword.lower()
        return [e for e in catalog if kw in e.cve_id.lower()
                or kw in e.vendor.lower() or kw in e.product.lower()
                or kw in e.description.lower() or kw in e.name.lower()]

    def get_recent(self, days: int = 7) -> List[KEVEntry]:
        catalog = self.fetch_catalog()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        return [e for e in catalog if e.date_added >= cutoff]

    def is_exploited(self, cve_id: str) -> Optional[KEVEntry]:
        catalog = self.fetch_catalog()
        cve_id = cve_id.upper().strip()
        for entry in catalog:
            if entry.cve_id == cve_id:
                return entry
        return None


# =============================================================================
#  EXPLOIT-DB CROSS-REFERENCE CLIENT
# =============================================================================

class ExploitDBClient:

    SEARCH_URL = "https://exploits.shodan.io/api/search"
    EDB_URL = "https://www.exploit-db.com"

    def __init__(self):
        if not HAS_REQUESTS:
            raise RuntimeError("requests library required: pip install requests")
        self.session: requests.Session = requests.Session()
        self.session.headers.update({
            "User-Agent": "FU-PERSON-CVE-Engine/1.0",
            "Accept": "text/html,application/json",
        })

    def search_cve(self, cve_id: str) -> List[ExploitRef]:
        cve_id = cve_id.upper().strip()
        results = self._query_exploitdb(cve_id)
        if not results:
            results = self._searchsploit_fallback(cve_id)
        return results

    def search_keyword(self, keyword: str) -> List[ExploitRef]:
        results = self._query_exploitdb(keyword)
        if not results:
            results = self._searchsploit_fallback(keyword)
        return results

    def _query_exploitdb(self, query: str) -> List[ExploitRef]:
        try:
            resp = self.session.get(
                f"{self.EDB_URL}/search",
                params={"q": query},
                timeout=15,
                allow_redirects=True,
            )
            if resp.status_code != 200:
                return []
            return self._parse_edb_html(resp.text, query)
        except RequestException:
            return []

    def _parse_edb_html(self, html: str, query: str) -> List[ExploitRef]:
        refs: List[ExploitRef] = []
        if not HAS_BS4:
            pattern = re.compile(
                r'/exploits/(\d+)"[^>]*>([^<]+)</a>.*?'
                r'class="platform"[^>]*>([^<]*)<',
                re.DOTALL,
            )
            for match in pattern.finditer(html):
                refs.append(ExploitRef(
                    edb_id=match.group(1),
                    title=match.group(2).strip(),
                    platform=match.group(3).strip(),
                    cve_id=query if query.startswith("CVE-") else "",
                ))
            return refs

        soup = BeautifulSoup(html, "html.parser")
        rows = soup.select("table.table tbody tr") or soup.select("tr.exploit_row")
        for row in rows[:50]:
            cols = row.find_all("td")
            if len(cols) < 5:
                continue
            link = cols[1].find("a") if len(cols) > 1 else None
            edb_id = ""
            title = ""
            if link:
                href = link.get("href", "")
                edb_match = re.search(r"/exploits/(\d+)", href)
                if edb_match:
                    edb_id = edb_match.group(1)
                title = link.get_text(strip=True)
            refs.append(ExploitRef(
                edb_id=edb_id,
                title=title,
                platform=cols[2].get_text(strip=True) if len(cols) > 2 else "",
                exploit_type=cols[4].get_text(strip=True) if len(cols) > 4 else "",
                cve_id=query if query.startswith("CVE-") else "",
            ))
        return refs

    @staticmethod
    def _searchsploit_fallback(query: str) -> List[ExploitRef]:
        import subprocess
        try:
            proc = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode != 0:
                return []
            data = json.loads(proc.stdout)
        except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
            return []

        refs: List[ExploitRef] = []
        for item in data.get("RESULTS_EXPLOIT", []):
            refs.append(ExploitRef(
                edb_id=str(item.get("EDB-ID", "")),
                title=item.get("Title", ""),
                platform=item.get("Platform", ""),
                exploit_type=item.get("Type", ""),
                language=item.get("Language", ""),
                cve_id=query if query.startswith("CVE-") else "",
            ))
        return refs


# =============================================================================
#  EPSS CLIENT (Exploit Prediction Scoring System)
# =============================================================================

class EPSSClient:

    API_URL = "https://api.first.org/data/v1/epss"

    def __init__(self):
        if not HAS_REQUESTS:
            raise RuntimeError("requests library required: pip install requests")
        self.session: requests.Session = requests.Session()
        self.session.headers.update({"User-Agent": "FU-PERSON-CVE-Engine/1.0"})

    def get_score(self, cve_id: str) -> Optional[EPSSScore]:
        results = self.get_scores([cve_id])
        return results[0] if results else None

    def get_scores(self, cve_ids: List[str]) -> List[EPSSScore]:
        if not cve_ids:
            return []
        scores: List[EPSSScore] = []
        for batch_start in range(0, len(cve_ids), 100):
            batch = cve_ids[batch_start:batch_start + 100]
            joined = ",".join(c.upper().strip() for c in batch)
            try:
                resp = self.session.get(
                    self.API_URL,
                    params={"cve": joined},
                    timeout=15,
                )
                resp.raise_for_status()
                data = resp.json()
            except RequestException as exc:
                C.fail(f"EPSS API error: {exc}")
                continue

            for item in data.get("data", []):
                scores.append(EPSSScore(
                    cve_id=item.get("cve", ""),
                    probability=float(item.get("epss", 0.0)),
                    percentile=float(item.get("percentile", 0.0)),
                    date=item.get("date", ""),
                ))
        return scores


# =============================================================================
#  LOCAL SQLITE CVE CACHE
# =============================================================================

class CVEDatabase:

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base = Path.home() / ".fuperson"
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / "cve_cache.db")
        self.db_path: str = db_path
        self.conn: sqlite3.Connection = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.init_db()

    def init_db(self) -> None:
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id      TEXT PRIMARY KEY,
                description TEXT,
                cvss_score  REAL DEFAULT 0.0,
                cvss_vector TEXT DEFAULT '',
                severity    TEXT DEFAULT 'UNKNOWN',
                cwe_ids     TEXT DEFAULT '[]',
                refs        TEXT DEFAULT '[]',
                cpe_matches TEXT DEFAULT '[]',
                published   TEXT DEFAULT '',
                modified    TEXT DEFAULT '',
                cached_at   TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS kev (
                cve_id           TEXT PRIMARY KEY,
                vendor           TEXT DEFAULT '',
                product          TEXT DEFAULT '',
                name             TEXT DEFAULT '',
                description      TEXT DEFAULT '',
                date_added       TEXT DEFAULT '',
                due_date         TEXT DEFAULT '',
                known_ransomware TEXT DEFAULT 'Unknown',
                cached_at        TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS exploits (
                edb_id       TEXT PRIMARY KEY,
                cve_id       TEXT DEFAULT '',
                title        TEXT DEFAULT '',
                platform     TEXT DEFAULT '',
                exploit_type TEXT DEFAULT '',
                language     TEXT DEFAULT '',
                cached_at    TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS watchlist (
                cve_id    TEXT PRIMARY KEY,
                notes     TEXT DEFAULT '',
                added_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS last_sync (
                source    TEXT PRIMARY KEY,
                synced_at TEXT DEFAULT (datetime('now'))
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
                cve_id, description, severity,
                content='cves', content_rowid='rowid'
            );
        """)
        self.conn.commit()

    def upsert_cve(self, cve: CVERecord) -> None:
        self.conn.execute("""
            INSERT INTO cves (cve_id, description, cvss_score, cvss_vector,
                              severity, cwe_ids, refs, cpe_matches,
                              published, modified, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                cvss_vector=excluded.cvss_vector,
                severity=excluded.severity,
                cwe_ids=excluded.cwe_ids,
                refs=excluded.refs,
                cpe_matches=excluded.cpe_matches,
                published=excluded.published,
                modified=excluded.modified,
                cached_at=excluded.cached_at
        """, (
            cve.cve_id, cve.description, cve.cvss.score, cve.cvss.vector,
            cve.cvss.severity, json.dumps(cve.cwe_ids), json.dumps(cve.references),
            json.dumps(cve.cpe_matches), cve.published, cve.modified,
        ))
        self.conn.commit()

    def upsert_kev(self, entry: KEVEntry) -> None:
        self.conn.execute("""
            INSERT INTO kev (cve_id, vendor, product, name, description,
                             date_added, due_date, known_ransomware, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor=excluded.vendor, product=excluded.product,
                name=excluded.name, description=excluded.description,
                date_added=excluded.date_added, due_date=excluded.due_date,
                known_ransomware=excluded.known_ransomware,
                cached_at=excluded.cached_at
        """, (
            entry.cve_id, entry.vendor, entry.product, entry.name,
            entry.description, entry.date_added, entry.due_date,
            entry.known_ransomware,
        ))
        self.conn.commit()

    def upsert_exploit(self, ref: ExploitRef) -> None:
        self.conn.execute("""
            INSERT INTO exploits (edb_id, cve_id, title, platform,
                                  exploit_type, language, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(edb_id) DO UPDATE SET
                cve_id=excluded.cve_id, title=excluded.title,
                platform=excluded.platform, exploit_type=excluded.exploit_type,
                language=excluded.language, cached_at=excluded.cached_at
        """, (
            ref.edb_id, ref.cve_id, ref.title, ref.platform,
            ref.exploit_type, ref.language,
        ))
        self.conn.commit()

    def sync_nvd(self, nvd: "NVDClient", days_back: int = 30) -> int:
        start = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
            "%Y-%m-%dT00:00:00.000"
        )
        end = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")
        C.info(f"Syncing NVD CVEs from last {days_back} days ...")
        vulns = nvd._paginate({"pubStartDate": start, "pubEndDate": end}, max_results=2000)
        count = 0
        for v in vulns:
            rec = NVDClient._parse_cve(v)
            self.upsert_cve(rec)
            count += 1
        self.conn.execute("""
            INSERT INTO last_sync (source, synced_at) VALUES ('nvd', datetime('now'))
            ON CONFLICT(source) DO UPDATE SET synced_at=excluded.synced_at
        """)
        self.conn.execute("INSERT INTO cve_fts(cve_fts) VALUES('rebuild')")
        self.conn.commit()
        C.ok(f"Synced {count} CVEs from NVD")
        return count

    def sync_kev(self, kev_client: "CISAKEVClient") -> int:
        C.info("Syncing CISA KEV catalog ...")
        entries = kev_client.fetch_catalog(force=True)
        for entry in entries:
            self.upsert_kev(entry)
        self.conn.execute("""
            INSERT INTO last_sync (source, synced_at) VALUES ('kev', datetime('now'))
            ON CONFLICT(source) DO UPDATE SET synced_at=excluded.synced_at
        """)
        self.conn.commit()
        C.ok(f"Synced {len(entries)} KEV entries")
        return len(entries)

    def search(self, query: str) -> List[Dict[str, Any]]:
        rows = self.conn.execute("""
            SELECT c.* FROM cves c
            JOIN cve_fts f ON c.rowid = f.rowid
            WHERE cve_fts MATCH ?
            ORDER BY c.cvss_score DESC LIMIT 100
        """, (query,)).fetchall()
        if not rows:
            like = f"%{query}%"
            rows = self.conn.execute("""
                SELECT * FROM cves
                WHERE cve_id LIKE ? OR description LIKE ?
                ORDER BY cvss_score DESC LIMIT 100
            """, (like, like)).fetchall()
        return [dict(r) for r in rows]

    def get_cached_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM cves WHERE cve_id = ?", (cve_id.upper(),)
        ).fetchone()
        return dict(row) if row else None

    def get_stats(self) -> Dict[str, Any]:
        cve_count = self.conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        kev_count = self.conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
        exploit_count = self.conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0]
        syncs = self.conn.execute("SELECT source, synced_at FROM last_sync").fetchall()
        sync_map = {row["source"]: row["synced_at"] for row in syncs}
        return {
            "total_cves": cve_count,
            "total_kev": kev_count,
            "total_exploits": exploit_count,
            "last_nvd_sync": sync_map.get("nvd", "never"),
            "last_kev_sync": sync_map.get("kev", "never"),
            "db_path": self.db_path,
        }

    def close(self) -> None:
        self.conn.close()


# =============================================================================
#  CVE ANALYZER
# =============================================================================

class CVEAnalyzer:

    def __init__(self, api_key: Optional[str] = None):
        self.nvd = NVDClient(api_key=api_key)
        self.kev = CISAKEVClient()
        self.epss = EPSSClient()
        self.edb = ExploitDBClient()

    def enrich(self, cve_id: str) -> Optional[EnrichedCVE]:
        cve_id = cve_id.upper().strip()
        C.info(f"Enriching {cve_id} ...")

        rec = self.nvd.search_cve(cve_id)
        if rec is None:
            C.fail(f"CVE {cve_id} not found in NVD")
            return None

        epss = self.epss.get_score(cve_id)
        kev_entry = self.kev.is_exploited(cve_id)
        exploits = self.edb.search_cve(cve_id)

        enriched = EnrichedCVE(
            cve_id=rec.cve_id,
            description=rec.description,
            cvss_score=rec.cvss.score,
            cvss_vector=rec.cvss.vector,
            severity=rec.cvss.severity,
            cwe_ids=rec.cwe_ids,
            references=rec.references,
            epss_probability=epss.probability if epss else 0.0,
            epss_percentile=epss.percentile if epss else 0.0,
            in_kev=kev_entry is not None,
            kev_due_date=kev_entry.due_date if kev_entry else "",
            known_ransomware=kev_entry.known_ransomware if kev_entry else "Unknown",
            exploit_available=len(exploits) > 0,
            exploit_count=len(exploits),
            published_date=rec.published,
            modified_date=rec.modified,
        )
        enriched.risk_score = self.risk_score(enriched)
        return enriched

    @staticmethod
    def risk_score(cve: EnrichedCVE) -> float:
        base = cve.cvss_score
        epss_weight = 1.0 + (cve.epss_probability * 3.0)
        kev_mult = 1.5 if cve.in_kev else 1.0
        exploit_mult = 1.2 if cve.exploit_available else 1.0
        score = base * epss_weight * kev_mult * exploit_mult
        return round(min(score, 10.0), 2)

    def trending(self, days: int = 7) -> List[KEVEntry]:
        return self.kev.get_recent(days=days)


# =============================================================================
#  CVE REPORTER
# =============================================================================

class CVEReporter:

    @staticmethod
    def severity_badge(score: float) -> str:
        if score >= 9.0:
            return f"{C.RED}{C.BLD}CRITICAL{C.R}"
        elif score >= 7.0:
            return f"{C.YLW}{C.BLD}HIGH{C.R}"
        elif score >= 4.0:
            return f"{C.BLU}MEDIUM{C.R}"
        else:
            return f"{C.GRN}LOW{C.R}"

    @staticmethod
    def severity_text(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        return "LOW"

    @classmethod
    def to_table(cls, cves: List[EnrichedCVE]) -> str:
        if not cves:
            return "  No results."
        lines: List[str] = []
        hdr = (f"  {C.BLD}{C.WHT}{'CVE ID':<18} {'CVSS':>5}  {'Severity':<10}"
               f" {'EPSS':>7}  {'KEV':>3}  {'Exploits':>8}  {'Risk':>5}{C.R}")
        sep = f"  {C.DIM}{'-' * 78}{C.R}"
        lines.append(sep)
        lines.append(hdr)
        lines.append(sep)
        for c in cves:
            badge = cls.severity_badge(c.cvss_score)
            kev_mark = f"{C.RED}YES{C.R}" if c.in_kev else f"{C.DIM}no{C.R}"
            exp_str = (f"{C.YLW}{c.exploit_count}{C.R}" if c.exploit_count
                       else f"{C.DIM}0{C.R}")
            risk_color = C.RED if c.risk_score >= 8 else C.YLW if c.risk_score >= 5 else C.GRN
            lines.append(
                f"  {C.CYN}{c.cve_id:<18}{C.R} {c.cvss_score:>5.1f}  {badge:<22}"
                f" {c.epss_probability:>6.3f}  {kev_mark:>15}  {exp_str:>20}"
                f"  {risk_color}{c.risk_score:>5.1f}{C.R}"
            )
        lines.append(sep)
        lines.append(f"  {C.DIM}{len(cves)} result(s){C.R}")
        return "\n".join(lines)

    @staticmethod
    def to_json(cves: List[EnrichedCVE]) -> str:
        return json.dumps([asdict(c) for c in cves], indent=2, default=str)

    @classmethod
    def to_html(cls, cves: List[EnrichedCVE]) -> str:
        sev_colors = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
            "MEDIUM": "#0d6efd", "LOW": "#198754",
        }
        rows: List[str] = []
        for c in cves:
            sev = cls.severity_text(c.cvss_score)
            color = sev_colors.get(sev, "#6c757d")
            kev = "YES" if c.in_kev else "no"
            rows.append(f"""      <tr>
        <td><code>{c.cve_id}</code></td>
        <td>{c.cvss_score:.1f}</td>
        <td><span style="background:{color};color:#fff;padding:2px 8px;
            border-radius:4px;font-size:0.85em">{sev}</span></td>
        <td>{c.epss_probability:.4f}</td>
        <td>{kev}</td>
        <td>{c.exploit_count}</td>
        <td><strong>{c.risk_score:.1f}</strong></td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;
            white-space:nowrap">{c.description[:120]}</td>
      </tr>""")

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>CVE Intelligence Report - FU PERSON</title>
<style>
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 2em; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: .5em; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
  th {{ background: #161b22; color: #58a6ff; padding: 10px 12px; text-align: left; border-bottom: 2px solid #30363d; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; }}
  tr:hover {{ background: #161b22; }}
  code {{ background: #1f2937; padding: 2px 6px; border-radius: 3px; }}
  .meta {{ color: #8b949e; font-size: 0.9em; margin-bottom: 1em; }}
</style></head><body>
  <h1>CVE Intelligence Report</h1>
  <p class="meta">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
   | {len(cves)} vulnerabilities | FU PERSON / FLLC</p>
  <table>
    <thead><tr>
      <th>CVE ID</th><th>CVSS</th><th>Severity</th><th>EPSS</th>
      <th>KEV</th><th>Exploits</th><th>Risk</th><th>Description</th>
    </tr></thead>
    <tbody>
{chr(10).join(rows)}
    </tbody>
  </table>
</body></html>"""

    @classmethod
    def detail_card(cls, cve: EnrichedCVE) -> str:
        lines = [
            f"\n  {C.CYN}{'=' * 70}{C.R}",
            f"  {C.BLD}{C.WHT}  CVE Detail: {cve.cve_id}{C.R}",
            f"  {C.CYN}{'=' * 70}{C.R}",
            f"",
            f"  {C.BLD}CVSS Score:{C.R}   {cve.cvss_score:.1f} / 10.0  "
            f"[{cls.severity_badge(cve.cvss_score)}]",
            f"  {C.BLD}CVSS Vector:{C.R}  {cve.cvss_vector or 'N/A'}",
            f"  {C.BLD}Risk Score:{C.R}   {cve.risk_score:.1f} / 10.0",
            f"  {C.BLD}Published:{C.R}    {cve.published_date[:10] if cve.published_date else 'N/A'}",
            f"  {C.BLD}Modified:{C.R}     {cve.modified_date[:10] if cve.modified_date else 'N/A'}",
            f"",
            f"  {C.BLD}EPSS:{C.R}         probability={cve.epss_probability:.4f}  "
            f"percentile={cve.epss_percentile:.4f}",
            f"  {C.BLD}CISA KEV:{C.R}     {'YES - Due: ' + cve.kev_due_date if cve.in_kev else 'No'}",
            f"  {C.BLD}Ransomware:{C.R}   {cve.known_ransomware}",
            f"  {C.BLD}Exploits:{C.R}     {cve.exploit_count} public exploit(s)",
            f"",
            f"  {C.BLD}CWE IDs:{C.R}      {', '.join(cve.cwe_ids) if cve.cwe_ids else 'N/A'}",
            f"",
            f"  {C.BLD}Description:{C.R}",
            f"  {C.DIM}{cve.description[:500]}{C.R}",
            f"",
        ]
        if cve.references:
            lines.append(f"  {C.BLD}References:{C.R}")
            for ref in cve.references[:10]:
                lines.append(f"    {C.DIM}-{C.R} {ref}")
        lines.append(f"\n  {C.CYN}{'=' * 70}{C.R}")
        return "\n".join(lines)


# =============================================================================
#  CLI INTERFACE
# =============================================================================

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cve_engine",
        description="FU PERSON :: CVE Intelligence Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python cve_engine.py lookup --cve CVE-2024-3400
  python cve_engine.py search --keyword "apache log4j" --days 365
  python cve_engine.py kev --recent 7
  python cve_engine.py epss --cve CVE-2024-3400
  python cve_engine.py enrich --cve CVE-2024-3400
  python cve_engine.py sync --days 30
  python cve_engine.py report --keyword "critical" --format html --output report.html
        """,
    )
    p.add_argument("--api-key", default=None, help="NVD API key (or set NVD_API_KEY env)")
    sub = p.add_subparsers(dest="command", required=True)

    # lookup
    lk = sub.add_parser("lookup", help="Look up a specific CVE by ID")
    lk.add_argument("--cve", required=True, help="CVE ID (e.g. CVE-2024-3400)")
    lk.add_argument("--format", choices=["table", "json", "html"], default="table")
    lk.add_argument("--output", default=None, help="Write output to file")

    # search
    sr = sub.add_parser("search", help="Search CVEs by keyword, product, or severity")
    sr.add_argument("--keyword", default=None, help="Keyword search")
    sr.add_argument("--product", default=None, help="CPE product name")
    sr.add_argument("--severity", default=None, choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    sr.add_argument("--days", type=int, default=30, help="Lookback days for date range")
    sr.add_argument("--format", choices=["table", "json", "html"], default="table")
    sr.add_argument("--output", default=None, help="Write output to file")

    # kev
    kv = sub.add_parser("kev", help="CISA Known Exploited Vulnerabilities")
    kv.add_argument("--cve", default=None, help="Check specific CVE in KEV")
    kv.add_argument("--keyword", default=None, help="Search KEV catalog")
    kv.add_argument("--recent", type=int, default=None, help="Recent KEV entries (days)")
    kv.add_argument("--format", choices=["table", "json"], default="table")

    # epss
    ep = sub.add_parser("epss", help="EPSS score lookup")
    ep.add_argument("--cve", required=True, help="CVE ID or comma-separated list")
    ep.add_argument("--format", choices=["table", "json"], default="table")

    # sync
    sy = sub.add_parser("sync", help="Sync local CVE cache from NVD/KEV")
    sy.add_argument("--days", type=int, default=30, help="Days to sync from NVD")
    sy.add_argument("--kev", action="store_true", help="Also sync CISA KEV")

    # enrich
    en = sub.add_parser("enrich", help="Enrich a CVE with all intelligence sources")
    en.add_argument("--cve", required=True, help="CVE ID to enrich")
    en.add_argument("--format", choices=["table", "json", "html"], default="table")
    en.add_argument("--output", default=None, help="Write output to file")

    # report
    rp = sub.add_parser("report", help="Generate a vulnerability report")
    rp.add_argument("--keyword", default=None, help="Keyword filter")
    rp.add_argument("--severity", default=None, choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    rp.add_argument("--days", type=int, default=7, help="Lookback days")
    rp.add_argument("--format", choices=["table", "json", "html"], default="table")
    rp.add_argument("--output", default=None, help="Write output to file")

    # stats
    sub.add_parser("stats", help="Show local cache statistics")

    return p


def _write_output(content: str, path: Optional[str]) -> None:
    if path:
        Path(path).write_text(content, encoding="utf-8")
        C.ok(f"Output written to {path}")
    else:
        C.p(content)


def _enrich_batch(analyzer: CVEAnalyzer, cve_records: List[CVERecord]) -> List[EnrichedCVE]:
    enriched: List[EnrichedCVE] = []
    epss_ids = [r.cve_id for r in cve_records]
    epss_map: Dict[str, EPSSScore] = {}
    if epss_ids:
        for s in analyzer.epss.get_scores(epss_ids):
            epss_map[s.cve_id] = s

    kev_catalog = analyzer.kev.fetch_catalog()
    kev_set: Dict[str, KEVEntry] = {e.cve_id: e for e in kev_catalog}

    for rec in cve_records:
        ep = epss_map.get(rec.cve_id)
        ke = kev_set.get(rec.cve_id)
        e = EnrichedCVE(
            cve_id=rec.cve_id,
            description=rec.description,
            cvss_score=rec.cvss.score,
            cvss_vector=rec.cvss.vector,
            severity=rec.cvss.severity,
            cwe_ids=rec.cwe_ids,
            references=rec.references,
            epss_probability=ep.probability if ep else 0.0,
            epss_percentile=ep.percentile if ep else 0.0,
            in_kev=ke is not None,
            kev_due_date=ke.due_date if ke else "",
            known_ransomware=ke.known_ransomware if ke else "Unknown",
            published_date=rec.published,
            modified_date=rec.modified,
        )
        e.risk_score = CVEAnalyzer.risk_score(e)
        enriched.append(e)

    enriched.sort(key=lambda x: x.risk_score, reverse=True)
    return enriched


def _kev_to_enriched(entries: List[KEVEntry]) -> List[EnrichedCVE]:
    return [
        EnrichedCVE(
            cve_id=e.cve_id,
            description=e.description,
            in_kev=True,
            kev_due_date=e.due_date,
            known_ransomware=e.known_ransomware,
            severity="HIGH",
        )
        for e in entries
    ]


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    C.banner("CVE INTELLIGENCE ENGINE v1.0")

    api_key = args.api_key or os.environ.get("NVD_API_KEY")
    reporter = CVEReporter()

    if args.command == "lookup":
        nvd = NVDClient(api_key=api_key)
        rec = nvd.search_cve(args.cve)
        if rec is None:
            C.fail(f"CVE {args.cve} not found")
            sys.exit(1)
        analyzer = CVEAnalyzer(api_key=api_key)
        enriched = analyzer.enrich(args.cve)
        if enriched is None:
            sys.exit(1)
        if args.format == "json":
            _write_output(reporter.to_json([enriched]), args.output)
        elif args.format == "html":
            _write_output(reporter.to_html([enriched]), args.output)
        else:
            _write_output(reporter.detail_card(enriched), args.output)

    elif args.command == "search":
        nvd = NVDClient(api_key=api_key)
        records: List[CVERecord] = []
        start = (datetime.now(timezone.utc) - timedelta(days=args.days)).strftime("%Y-%m-%d")
        if args.keyword:
            C.info(f"Searching NVD for keyword: {args.keyword}")
            records = nvd.search_keyword(args.keyword, start_date=start)
        elif args.product:
            C.info(f"Searching NVD for product: {args.product}")
            records = nvd.search_product(args.product)
        elif args.severity:
            C.info(f"Searching NVD for severity: {args.severity}")
            records = nvd.search_severity(args.severity, start_date=start)
        else:
            C.fail("Provide --keyword, --product, or --severity")
            sys.exit(1)
        C.ok(f"Found {len(records)} CVE(s)")
        if not records:
            sys.exit(0)
        analyzer = CVEAnalyzer(api_key=api_key)
        enriched = _enrich_batch(analyzer, records)
        if args.format == "json":
            _write_output(reporter.to_json(enriched), args.output)
        elif args.format == "html":
            _write_output(reporter.to_html(enriched), args.output)
        else:
            _write_output(reporter.to_table(enriched), args.output)

    elif args.command == "kev":
        kev_client = CISAKEVClient()
        entries: List[KEVEntry] = []
        if args.cve:
            entry = kev_client.is_exploited(args.cve)
            if entry:
                C.ok(f"{args.cve} IS in CISA KEV (due: {entry.due_date})")
                entries = [entry]
            else:
                C.info(f"{args.cve} is NOT in CISA KEV")
        elif args.keyword:
            entries = kev_client.search(args.keyword)
            C.ok(f"Found {len(entries)} KEV match(es)")
        elif args.recent is not None:
            entries = kev_client.get_recent(days=args.recent)
            C.ok(f"{len(entries)} KEV entries added in last {args.recent} day(s)")
        else:
            entries = kev_client.fetch_catalog()
            C.ok(f"Full catalog: {len(entries)} entries")
        if entries:
            enriched = _kev_to_enriched(entries)
            if args.format == "json":
                C.p(reporter.to_json(enriched))
            else:
                C.p(reporter.to_table(enriched))

    elif args.command == "epss":
        epss_client = EPSSClient()
        cve_ids = [c.strip() for c in args.cve.split(",")]
        scores = epss_client.get_scores(cve_ids)
        if not scores:
            C.fail("No EPSS data returned")
            sys.exit(1)
        if args.format == "json":
            C.p(json.dumps([asdict(s) for s in scores], indent=2))
        else:
            hdr = f"  {C.BLD}{'CVE ID':<18} {'Probability':>11} {'Percentile':>10}  {'Date'}{C.R}"
            C.p(f"  {C.DIM}{'-' * 60}{C.R}")
            C.p(hdr)
            C.p(f"  {C.DIM}{'-' * 60}{C.R}")
            for s in scores:
                prob_color = C.RED if s.probability > 0.5 else C.YLW if s.probability > 0.1 else C.GRN
                C.p(f"  {C.CYN}{s.cve_id:<18}{C.R} "
                    f"{prob_color}{s.probability:>10.6f}{C.R} "
                    f"{s.percentile:>10.4f}  {C.DIM}{s.date}{C.R}")
            C.p(f"  {C.DIM}{'-' * 60}{C.R}")

    elif args.command == "sync":
        db = CVEDatabase()
        nvd = NVDClient(api_key=api_key)
        cve_count = db.sync_nvd(nvd, days_back=args.days)
        kev_count = 0
        if args.kev:
            kev_client = CISAKEVClient()
            kev_count = db.sync_kev(kev_client)
        C.ok(f"Sync complete: {cve_count} CVEs, {kev_count} KEV entries")
        stats = db.get_stats()
        C.info(f"Cache: {stats['total_cves']} CVEs, {stats['total_kev']} KEV, "
               f"{stats['total_exploits']} exploits")
        db.close()

    elif args.command == "enrich":
        analyzer = CVEAnalyzer(api_key=api_key)
        enriched = analyzer.enrich(args.cve)
        if enriched is None:
            sys.exit(1)
        C.ok(f"Risk score: {enriched.risk_score:.1f}/10.0")
        if args.format == "json":
            _write_output(reporter.to_json([enriched]), args.output)
        elif args.format == "html":
            _write_output(reporter.to_html([enriched]), args.output)
        else:
            _write_output(reporter.detail_card(enriched), args.output)

    elif args.command == "report":
        nvd = NVDClient(api_key=api_key)
        start = (datetime.now(timezone.utc) - timedelta(days=args.days)).strftime("%Y-%m-%d")
        records: List[CVERecord] = []
        if args.keyword:
            records = nvd.search_keyword(args.keyword, start_date=start)
        elif args.severity:
            records = nvd.search_severity(args.severity, start_date=start)
        else:
            C.info(f"Fetching CRITICAL + HIGH CVEs from last {args.days} days ...")
            records = nvd.search_severity("CRITICAL", start_date=start)
            records += nvd.search_severity("HIGH", start_date=start)
        C.ok(f"Found {len(records)} CVE(s) for report")
        if not records:
            C.info("No results to report")
            sys.exit(0)
        analyzer = CVEAnalyzer(api_key=api_key)
        enriched = _enrich_batch(analyzer, records)
        if args.format == "json":
            _write_output(reporter.to_json(enriched), args.output)
        elif args.format == "html":
            _write_output(reporter.to_html(enriched), args.output)
        else:
            _write_output(reporter.to_table(enriched), args.output)

    elif args.command == "stats":
        db = CVEDatabase()
        stats = db.get_stats()
        C.p(f"\n  {C.BLD}{C.WHT}Local CVE Cache Statistics{C.R}")
        C.p(f"  {C.DIM}{'-' * 40}{C.R}")
        C.p(f"  {C.BLD}Database:{C.R}       {stats['db_path']}")
        C.p(f"  {C.BLD}Total CVEs:{C.R}     {stats['total_cves']}")
        C.p(f"  {C.BLD}Total KEV:{C.R}      {stats['total_kev']}")
        C.p(f"  {C.BLD}Total Exploits:{C.R} {stats['total_exploits']}")
        C.p(f"  {C.BLD}Last NVD Sync:{C.R}  {stats['last_nvd_sync']}")
        C.p(f"  {C.BLD}Last KEV Sync:{C.R}  {stats['last_kev_sync']}")
        C.p(f"  {C.DIM}{'-' * 40}{C.R}\n")
        db.close()


if __name__ == "__main__":
    main()
