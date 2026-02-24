#!/usr/bin/env python3
"""Glob resolution testing for LOLGlobs entries (platform-aware).

Usage:
  python scripts/validate_globs.py --platform linux
  python scripts/validate_globs.py --platform macos
  python scripts/validate_globs.py --platform windows-cmd
  python scripts/validate_globs.py --platform powershell

PASS  — pattern resolved and the expected binary/cmdlet name was found
FAIL  — pattern resolved but result doesn't contain expected name (non-fatal)
SKIP  — binary not installed on this runner, or pattern couldn't be parsed

Exit 0 unless at least one FAIL.
"""

import argparse
import glob as glob_module
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent

_USE_COLOR = sys.stdout.isatty() or bool(os.environ.get("CI"))
GREEN = "\033[32m" if _USE_COLOR else ""
RED = "\033[31m" if _USE_COLOR else ""
YELLOW = "\033[33m" if _USE_COLOR else ""
RESET = "\033[0m" if _USE_COLOR else ""


def _parse_front_matter(filepath):
    content = Path(filepath).read_text(encoding="utf-8")
    if not content.startswith("---"):
        return None
    end = content.find("\n---", 3)
    if end == -1:
        return None
    return yaml.safe_load(content[3:end])


def _get_entries(platform):
    """Return list of (Path, dict) for every entry matching *platform*."""
    return [
        (p, d)
        for p in sorted((ROOT / "_globs").rglob("*.md"))
        if (d := _parse_front_matter(p)) and d.get("Platform") == platform
    ]


def _result(status, label, detail=""):
    colour = {"PASS": GREEN, "FAIL": RED, "SKIP": YELLOW}[status]
    suffix = f"  [{detail}]" if detail else ""
    print(f"  {colour}{status}{RESET}  {label}{suffix}")


def _accepted_names(entry):
    """Lowercase set of binary basenames that count as a valid resolution.

    Includes the entry Name plus every basename extracted from path-like
    BinaryPath entries, so aliases like nc/netcat/ncat all pass.
    Descriptive strings (e.g. "PowerShell cmdlet") are ignored.
    """
    names = {entry["Name"].lower()}
    for bp in entry.get("BinaryPath", []):
        # Only extract basenames from actual paths (contain a path separator)
        if "/" in bp or "\\" in bp:
            basename = os.path.basename(bp).lower()
            if basename:
                names.add(basename)
    return names


# ── Linux / macOS ─────────────────────────────────────────────────────────────


def test_posix(entries):
    passed = failed = skipped = 0
    path_dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d]

    for _, entry in entries:
        name = entry["Name"]
        for i, pat in enumerate(entry.get("Patterns", [])):
            pattern_str = pat.get("Pattern", "")
            wildcards = pat.get("Wildcards", [])
            label = f"{name}  pattern[{i}]  {pattern_str!r}"

            if not wildcards:
                _result("SKIP", label, "alias entry, no wildcards")
                skipped += 1
                continue

            accepted = _accepted_names(entry)

            if "/" in pattern_str:
                # Absolute / relative path glob
                try:
                    matches = glob_module.glob(pattern_str)
                except Exception as exc:
                    _result("SKIP", label, f"glob error: {exc}")
                    skipped += 1
                    continue

                if not matches:
                    _result("SKIP", label, "no path matches — binary not installed?")
                    skipped += 1
                elif any(os.path.basename(m).lower() in accepted for m in matches):
                    _result("PASS", label)
                    passed += 1
                else:
                    basenames = [os.path.basename(m) for m in matches[:3]]
                    _result(
                        "FAIL", label, f"matches {basenames} not in accepted {accepted}"
                    )
                    failed += 1
            else:
                # Bare command — search every directory in PATH
                all_matches = []
                for d in path_dirs:
                    try:
                        all_matches.extend(
                            glob_module.glob(os.path.join(d, pattern_str))
                        )
                    except Exception:
                        pass

                if not all_matches:
                    _result("SKIP", label, "no PATH matches — binary not installed?")
                    skipped += 1
                elif any(os.path.basename(m).lower() in accepted for m in all_matches):
                    _result("PASS", label)
                    passed += 1
                else:
                    basenames = [os.path.basename(m) for m in all_matches[:3]]
                    _result(
                        "FAIL", label, f"matches {basenames} not in accepted {accepted}"
                    )
                    failed += 1

    return passed, failed, skipped


# ── Windows CMD ───────────────────────────────────────────────────────────────
# 'where [/r Dir] pattern'  inside a CMD for-loop single-quoted string
_WHERE_RE = re.compile(r"'where\s+(.+?)'", re.IGNORECASE)
# 'dir /b path\glob'
_DIR_B_RE = re.compile(r"'dir\s+/b\s+(.+?)'", re.IGNORECASE)


def _extract_cmd_glob(pattern_str):
    """Return ('where', arg) or ('dir', arg), or (None, None)."""
    m = _WHERE_RE.search(pattern_str)
    if m:
        return "where", m.group(1).strip()
    m = _DIR_B_RE.search(pattern_str)
    if m:
        return "dir", m.group(1).strip()
    return None, None


def test_windows_cmd(entries):
    passed = failed = skipped = 0

    for _, entry in entries:
        name = entry["Name"]
        for i, pat in enumerate(entry.get("Patterns", [])):
            pattern_str = pat.get("Pattern", "")
            wildcards   = pat.get("Wildcards", [])
            label = f"{name}  pattern[{i}]  {pattern_str!r}"

            if not wildcards:
                _result("SKIP", label, "no wildcards, alias-style entry")
                skipped += 1
                continue

            kind, glob_arg = _extract_cmd_glob(pattern_str)
            if kind is None:
                _result("SKIP", label, "couldn't parse glob from pattern")
                skipped += 1
                continue

            if kind == "where":
                # where.exe accepts the same args we extracted, including /r
                cmd = ["where"] + glob_arg.split()
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=30
                    )
                    output = proc.stdout.strip()
                except FileNotFoundError:
                    _result("SKIP", label, "where.exe not found")
                    skipped += 1
                    continue
                except Exception as exc:
                    _result("SKIP", label, f"subprocess error: {exc}")
                    skipped += 1
                    continue

                accepted = _accepted_names(entry)
                if not output:
                    _result(
                        "SKIP",
                        label,
                        "where returned no output — binary not installed?",
                    )
                    skipped += 1
                elif any(n in output.lower() for n in accepted):
                    _result("PASS", label)
                    passed += 1
                else:
                    _result(
                        "FAIL",
                        label,
                        f"where output doesn't contain any of {accepted}: {output[:80]!r}",
                    )
                    failed += 1

            else:  # kind == "dir" — use Python glob on the path
                try:
                    matches = glob_module.glob(glob_arg)
                except Exception as exc:
                    _result("SKIP", label, f"glob error: {exc}")
                    skipped += 1
                    continue

                if not matches:
                    _result(
                        "SKIP",
                        label,
                        f"no matches for {glob_arg!r} — binary not installed?",
                    )
                    skipped += 1
                elif any(name.lower() in os.path.basename(m).lower() for m in matches):
                    _result("PASS", label)
                    passed += 1
                else:
                    basenames = [os.path.basename(m) for m in matches[:3]]
                    _result(
                        "FAIL", label, f"dir matches {basenames} don't contain '{name}'"
                    )
                    failed += 1

    return passed, failed, skipped


# ── PowerShell ────────────────────────────────────────────────────────────────
# (gcm/Get-Command Pattern) or (gal/Get-Alias Pattern)
_PS_GCM_RE = re.compile(r"\(\s*(?:gcm|Get-Command)\s+([^)]+)\)", re.IGNORECASE)
_PS_GAL_RE = re.compile(r"\(\s*(?:gal|Get-Alias)\s+([^)]+)\)", re.IGNORECASE)


def _extract_ps_glob(pattern_str):
    """Return (kind, glob_arg) where kind is 'gcm' or 'gal', or (None, None)."""
    m = _PS_GCM_RE.search(pattern_str)
    if m:
        return "gcm", m.group(1).strip()
    m = _PS_GAL_RE.search(pattern_str)
    if m:
        return "gal", m.group(1).strip()
    return None, None


def test_powershell(entries):
    passed = failed = skipped = 0

    for _, entry in entries:
        name = entry["Name"]
        for i, pat in enumerate(entry.get("Patterns", [])):
            pattern_str = pat.get("Pattern", "")
            wildcards   = pat.get("Wildcards", [])
            label = f"{name}  pattern[{i}]  {pattern_str!r}"

            if not wildcards:
                _result("SKIP", label, "alias entry, no wildcards")
                skipped += 1
                continue

            kind, glob_arg = _extract_ps_glob(pattern_str)
            if kind is None:
                _result("SKIP", label, "couldn't parse gcm/Get-Command or gal/Get-Alias glob")
                skipped += 1
                continue

            if kind == "gcm":
                ps_script = (
                    f"Get-Command '{glob_arg}' -ErrorAction SilentlyContinue"
                    f" | Select-Object -ExpandProperty Name"
                )
            else:  # gal — resolve alias to its target cmdlet name
                ps_script = (
                    f"Get-Alias '{glob_arg}' -ErrorAction SilentlyContinue"
                    f" | Select-Object -ExpandProperty Definition"
                )

            try:
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    capture_output=True, text=True, timeout=30,
                )
                output = proc.stdout.strip()
            except FileNotFoundError:
                _result("SKIP", label, "powershell not found on PATH")
                skipped += 1
                continue
            except Exception as exc:
                _result("SKIP", label, f"subprocess error: {exc}")
                skipped += 1
                continue

            if not output:
                _result("SKIP", label, f"{kind} returned nothing — not available?")
                skipped += 1
            elif kind == "gal" and "\n" in output:
                # Multiple aliases matched — ambiguous, mirrors real-world failure
                aliases = output.replace("\n", ", ")[:80]
                _result("SKIP", label, f"gal matched multiple aliases (ambiguous): {aliases}")
                skipped += 1
            elif name.lower() in output.lower():
                _result("PASS", label)
                passed += 1
            else:
                _result("FAIL", label, f"resolved to '{output}', expected '{name}'")
                failed += 1

    return passed, failed, skipped


def main():
    parser = argparse.ArgumentParser(
        description="Test glob resolution for LOLGlobs entries"
    )
    parser.add_argument(
        "--platform",
        required=True,
        choices=["linux", "macos", "windows-cmd", "powershell"],
        help="Platform entries to test",
    )
    args = parser.parse_args()

    entries = _get_entries(args.platform)
    if not entries:
        print(f"No entries found for platform '{args.platform}'")
        sys.exit(0)

    print(f"\nTesting {len(entries)} '{args.platform}' entries...\n")

    dispatch = {
        "linux": test_posix,
        "macos": test_posix,
        "windows-cmd": test_windows_cmd,
        "powershell": test_powershell,
    }
    passed, failed, skipped = dispatch[args.platform](entries)

    total = passed + failed + skipped
    print(
        f"\nResults: {GREEN}{passed} passed{RESET}, "
        f"{RED}{failed} failed{RESET}, "
        f"{YELLOW}{skipped} skipped{RESET} "
        f"({total} patterns total)"
    )

    if failed:
        print(f"\nGLOB VALIDATION FAILED: {failed} pattern(s) resolved incorrectly.")
        sys.exit(1)

    print("Glob validation passed.")


if __name__ == "__main__":
    main()
