#!/usr/bin/env python3
"""Fail CI when a security exception is malformed, unapproved, or expired."""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

REQUIRED = {
    "id", "control", "reason", "risk", "compensating_control",
    "owner", "approver", "approved_on", "expires_on", "tracking_issue", "status",
}


def main() -> int:
    path = Path("security-exceptions.json")
    if not path.exists():
        print("ERROR: security-exceptions.json is missing; use [] when no exceptions exist.")
        return 1
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot parse {path}: {exc}")
        return 1
    if not isinstance(entries, list):
        print("ERROR: security-exceptions.json must contain a JSON array.")
        return 1

    today = date.today()
    errors: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        prefix = f"exception[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = sorted(REQUIRED - entry.keys())
        if missing:
            errors.append(f"{prefix} missing fields: {', '.join(missing)}")
            continue
        if entry["status"] != "approved":
            errors.append(f"{prefix}.status must be approved")
        identifier = str(entry["id"]).strip()
        if not identifier or identifier in seen:
            errors.append(f"{prefix} has an empty or duplicate id")
        seen.add(identifier)
        for key in REQUIRED - {"approved_on", "expires_on"}:
            if not str(entry[key]).strip():
                errors.append(f"{prefix}.{key} must not be empty")
        try:
            approved = date.fromisoformat(entry["approved_on"])
            expires = date.fromisoformat(entry["expires_on"])
            if approved > today:
                errors.append(f"{prefix}.approved_on cannot be in the future")
            if expires <= approved:
                errors.append(f"{prefix}.expires_on must be after approved_on")
            if expires < today:
                errors.append(f"{prefix} expired on {expires.isoformat()}")
        except (TypeError, ValueError):
            errors.append(f"{prefix} approved_on/expires_on must use YYYY-MM-DD")
    if errors:
        print("Security exception validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"Security exception validation passed ({len(entries)} active exception(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
