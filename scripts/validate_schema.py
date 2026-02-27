#!/usr/bin/env python3
"""Schema validation for all LOLGlobs entries (_globs/**/*.md).

Checks:
  - Required fields present
  - Platform / Category match enum values from _data/*.yml
  - Pattern sub-fields (Pattern, Wildcards, Notes) present
  - Wildcards values are in {"?", "*", "[]"}
  - Wildcards consistency: listed wildcard char appears in Pattern string
  - MitreID format: T####[.###]
  - Directory/Platform match
  - No duplicate Name+Platform pairs

Exit 0 on success, non-zero on any failure.
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
REQUIRED_FIELDS = [
    "Name",
    "Description",
    "Platform",
    "BinaryPath",
    "Category",
    "MitreID",
    "Patterns",
]
REQUIRED_PATTERN_FIELDS = ["Pattern", "Wildcards", "Notes"]
VALID_WILDCARDS = {"?", "*", "[]", "-clike"}
BRACKET_RANGE_RE = re.compile(r"^\[.+\]$")  # [abc], [a-z], [d-f], etc.
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Map wildcard label -> character that must appear in the Pattern string
WILDCARD_CHARS = {"?": "?", "*": "*", "[]": "[", "-clike": "-clike"}


def load_enums():
    """Load valid Platform and Category IDs from _data/*.yml."""
    with open(ROOT / "_data" / "platforms.yml", encoding="utf-8") as f:
        platforms = yaml.safe_load(f)
    with open(ROOT / "_data" / "categories.yml", encoding="utf-8") as f:
        categories = yaml.safe_load(f)
    return {p["id"] for p in platforms}, {c["id"] for c in categories}


def parse_front_matter(filepath):
    """Return parsed YAML front matter dict, or raise on malformed input."""
    content = Path(filepath).read_text(encoding="utf-8")
    if not content.startswith("---"):
        raise ValueError("missing opening ---")
    end = content.find("\n---", 3)
    if end == -1:
        raise ValueError("unclosed front matter (no closing ---)")
    return yaml.safe_load(content[3:end])


def validate_entry(filepath, data, valid_platforms, valid_categories, seen):
    """Validate one entry. Returns a list of error strings (empty = OK)."""
    errors = []
    rel = filepath.relative_to(ROOT)

    # ── Required fields ───────────────────────────────────────────────────────
    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        for f in missing:
            errors.append(f"{rel}: Missing required field '{f}'")
        return errors  # can't validate further without required fields

    # ── Enum: Platform ────────────────────────────────────────────────────────
    platform = data["Platform"]
    if platform not in valid_platforms:
        errors.append(
            f"{rel}: Invalid Platform '{platform}' (valid: {sorted(valid_platforms)})"
        )

    # ── Enum: Category ────────────────────────────────────────────────────────
    category = data["Category"]
    if category not in valid_categories:
        errors.append(
            f"{rel}: Invalid Category '{category}' (valid: {sorted(valid_categories)})"
        )

    # ── MitreID format ────────────────────────────────────────────────────────
    mitre = str(data["MitreID"])
    if not MITRE_RE.match(mitre):
        errors.append(f"{rel}: Invalid MitreID '{mitre}' (expected T####[.###])")

    # ── BinaryPath type ───────────────────────────────────────────────────────
    if not isinstance(data["BinaryPath"], list):
        errors.append(f"{rel}: BinaryPath must be a YAML list")

    # ── Directory / Platform consistency ─────────────────────────────────────
    dir_name = filepath.parent.name
    if dir_name in valid_platforms and platform != dir_name:
        errors.append(
            f"{rel}: Platform '{platform}' doesn't match directory '{dir_name}'"
        )

    # ── Duplicate check ───────────────────────────────────────────────────────
    key = (data["Name"].lower(), platform)
    if key in seen:
        errors.append(
            f"{rel}: Duplicate entry Name='{data['Name']}' "
            f"Platform='{platform}' (first seen in {seen[key]})"
        )
    else:
        seen[key] = str(rel)

    # ── Patterns ──────────────────────────────────────────────────────────────
    patterns = data["Patterns"]
    if not isinstance(patterns, list) or len(patterns) == 0:
        errors.append(f"{rel}: Patterns must be a non-empty list")
        return errors

    for i, pat in enumerate(patterns):
        prefix = f"{rel}: Patterns[{i}]"

        if not isinstance(pat, dict):
            errors.append(f"{prefix}: must be a mapping, got {type(pat).__name__}")
            continue

        for pf in REQUIRED_PATTERN_FIELDS:
            if pf not in pat:
                errors.append(f"{prefix}: Missing field '{pf}'")

        if "Pattern" not in pat or "Wildcards" not in pat:
            continue  # already reported missing fields

        pattern_str = str(pat["Pattern"])
        wildcards = pat["Wildcards"]

        if not isinstance(wildcards, list):
            errors.append(f"{prefix}: Wildcards must be a list")
            continue

        for wc in wildcards:
            # Valid wildcard value? Accepts *, ?, [], or any [X-Y]/[abc] range.
            is_bracket_range = BRACKET_RANGE_RE.match(wc) is not None
            if wc not in VALID_WILDCARDS and not is_bracket_range:
                errors.append(
                    f"{prefix}: Invalid Wildcards value '{wc}' "
                    f"(valid: {sorted(VALID_WILDCARDS)} or bracket ranges like [a-z])"
                )
                continue
            # Char consistency: bracket ranges require '[' in pattern
            char = WILDCARD_CHARS.get(wc, "[")
            if char not in pattern_str:
                errors.append(
                    f"{prefix}: Wildcard '{wc}' listed but '{char}' "
                    f"not found in Pattern string: {pattern_str!r}"
                )

    return errors


def main():
    valid_platforms, valid_categories = load_enums()

    globs_dir = ROOT / "_globs"
    entry_files = sorted(globs_dir.rglob("*.md"))
    if not entry_files:
        print("ERROR: No entries found under _globs/", file=sys.stderr)
        sys.exit(1)

    all_errors = []
    seen = {}

    for path in entry_files:
        try:
            data = parse_front_matter(path)
        except Exception as exc:
            all_errors.append(f"{path.relative_to(ROOT)}: Parse error — {exc}")
            continue

        if data is None:
            all_errors.append(f"{path.relative_to(ROOT)}: Empty front matter")
            continue

        all_errors.extend(
            validate_entry(path, data, valid_platforms, valid_categories, seen)
        )

    if all_errors:
        print(f"SCHEMA VALIDATION FAILED ({len(all_errors)} error(s)):\n")
        for err in all_errors:
            print(f"  ERROR: {err}")
        sys.exit(1)

    print(f"Schema validation passed: {len(entry_files)} entries checked, 0 errors.")


if __name__ == "__main__":
    main()
