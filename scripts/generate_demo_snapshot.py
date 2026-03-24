#!/usr/bin/env python3
"""Generate a minimal placeholder CVE snapshot for release packaging.

Used as a fallback when the NVD API is not available during release builds.
"""

import json
import sys
from datetime import datetime, timezone


def main():
    output_path = sys.argv[1] if len(sys.argv) > 1 else "dist/cve-snapshot.json"
    snapshot = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "note": "CVE sync not available without NVD_API_KEY",
        "results": [],
    }
    with open(output_path, "w") as fh:
        json.dump(snapshot, fh, indent=2)
    print(f"Placeholder CVE snapshot written to {output_path}")


if __name__ == "__main__":
    main()
