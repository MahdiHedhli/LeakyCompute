#!/usr/bin/env python3
"""Build / merge filtered seed catalogs from archive JSON dumps."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

EXPLOIT_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"^/etc",
    r"^/root",
    r"^/var",
    r"^/tmp",
    r"id_rsa",
    r"authorized_keys",
    r"shadow",
    r"passwd",
    r"aws_credentials",
    r"\.aws",
    r"169\.254\.",
    r"metadata\.google",
    r"kubernetes\.default",
    r"webhook\.site",
    r"ssrf",
    r"postman-echo",
    r"^https?://",
    r"inj_",
    r"pwn",
    r"getshadow",
    r"read__root",
    r"x__root",
    r"file://",
    r"gopher://",
]


def is_exploit(name: str) -> bool:
    n = name.lower()
    for p in EXPLOIT_PATTERNS:
        if re.search(p, n):
            return True
    if n.count("__") >= 2 and ("root" in n or "ssh" in n or "etc" in n):
        return True
    return False


def load_entries(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "models" in data:
        return data["models"]
    if isinstance(data, list):
        return data
    raise SystemExit(f"Unrecognized format: {path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", type=Path, help="Raw or seed JSON files")
    ap.add_argument("-o", "--output", type=Path, default=Path("data/seed-models.json"))
    args = ap.parse_args()

    by_name: dict[str, dict] = {}
    filtered = 0
    raw_n = 0
    for path in args.inputs:
        for m in load_entries(path):
            raw_n += 1
            name = m.get("model") or ""
            if not name or is_exploit(name) or len(name) > 200:
                filtered += 1
                continue
            hosts = int(m.get("hosts") or 0)
            prev = by_name.get(name)
            if not prev or hosts > prev["hosts"]:
                by_name[name] = {
                    "model": name,
                    "hosts": hosts,
                    "size": m.get("size") or "?",
                    "num": m.get("num"),
                    "seen": m.get("seen"),
                    "source": m.get("source") or f"merge:{path.name}",
                    "validated": bool(m.get("validated", False)),
                }

    models = sorted(by_name.values(), key=lambda x: (-x["hosts"], x["model"]))
    total_hosts = sum(m["hosts"] for m in models)
    seed = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": [str(p) for p in args.inputs],
        "snapshot": {
            "models": len(models),
            "hosts": total_hosts,
            "filtered_exploit_like": filtered,
            "raw_entries": raw_n,
        },
        "models": models,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(seed, indent=2) + "\n")
    print(json.dumps(seed["snapshot"], indent=2))
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
