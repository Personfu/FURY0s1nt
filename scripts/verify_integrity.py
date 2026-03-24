#!/usr/bin/env python3
"""SHA-256 integrity verification for FU-PERSON project files."""

import hashlib
import os
import sys

SCAN_DIRS = ["core", "payloads", "usb_payload", "firmware", "web"]
SCAN_EXTENSIONS = {".py", ".ps1", ".sh", ".bat", ".html", ".css", ".js", ".ino", ".h"}
DEFAULT_MANIFEST = "CHECKSUMS.sha256"


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_checksums(root_dir: str) -> dict[str, str]:
    checksums = {}
    for scan_dir in SCAN_DIRS:
        target = os.path.join(root_dir, scan_dir)
        if not os.path.isdir(target):
            continue
        for dirpath, _, filenames in os.walk(target):
            for fname in sorted(filenames):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SCAN_EXTENSIONS:
                    continue
                full = os.path.join(dirpath, fname)
                rel = os.path.relpath(full, root_dir).replace("\\", "/")
                checksums[rel] = sha256_file(full)
    return checksums


def save_manifest(checksums: dict[str, str], filepath: str = DEFAULT_MANIFEST) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        for path in sorted(checksums):
            f.write(f"{checksums[path]}  {path}\n")
    print(f"[+] Manifest written: {filepath} ({len(checksums)} files)")


def load_manifest(filepath: str = DEFAULT_MANIFEST) -> dict[str, str]:
    checksums = {}
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            digest, path = line.split("  ", 1)
            checksums[path] = digest
    return checksums


def verify_manifest(filepath: str = DEFAULT_MANIFEST, diff_only: bool = False) -> None:
    if not os.path.isfile(filepath):
        print(f"[-] Manifest not found: {filepath}")
        print("    Run 'python verify_integrity.py generate' first.")
        sys.exit(1)

    expected = load_manifest(filepath)
    root_dir = os.path.dirname(os.path.abspath(filepath))

    passed = 0
    failed = 0
    missing = 0

    for path in sorted(expected):
        full = os.path.join(root_dir, path.replace("/", os.sep))
        if not os.path.isfile(full):
            missing += 1
            if not diff_only:
                print(f"  [MISSING]  {path}")
            continue

        actual = sha256_file(full)
        if actual == expected[path]:
            passed += 1
            if not diff_only:
                print(f"  [PASS]     {path}")
        else:
            failed += 1
            print(f"  [FAIL]     {path}")
            if diff_only:
                print(f"             expected: {expected[path]}")
                print(f"             actual:   {actual}")

    total = passed + failed + missing
    print()
    print(f"[*] Summary: {total} files verified, "
          f"{passed} passed, {failed} failed, {missing} missing")

    if failed or missing:
        sys.exit(1)


def usage():
    print("Usage: python verify_integrity.py <command>")
    print()
    print("Commands:")
    print("  generate   Compute SHA-256 checksums and write CHECKSUMS.sha256")
    print("  verify     Verify all files against the manifest")
    print("  diff       Show only changed or missing files")


def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        usage()
        sys.exit(0 if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help") else 1)

    command = sys.argv[1].lower()
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if command == "generate":
        checksums = generate_checksums(root_dir)
        if not checksums:
            print("[-] No files found to checksum.")
            sys.exit(1)
        manifest_path = os.path.join(root_dir, DEFAULT_MANIFEST)
        save_manifest(checksums, manifest_path)

    elif command == "verify":
        manifest_path = os.path.join(root_dir, DEFAULT_MANIFEST)
        verify_manifest(manifest_path, diff_only=False)

    elif command == "diff":
        manifest_path = os.path.join(root_dir, DEFAULT_MANIFEST)
        verify_manifest(manifest_path, diff_only=True)

    else:
        print(f"[-] Unknown command: {command}")
        usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
