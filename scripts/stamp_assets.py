#!/usr/bin/env python3
"""
Stamp CSS/JS URLs in public/ with a content hash.

A returning visitor keeps whatever stylesheet their browser cached, so a shipped
change can look to them like work that was never done — which is exactly how it
looked twice in one morning. Hashing the URL makes the browser fetch a new asset
because it is a different URL, without any cache-control tuning.

Run before committing a change to public/css or public/js:
    python3 scripts/stamp_assets.py
"""
import hashlib, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[1] / "public"
ASSETS = {
    "css/style.css": r'href="css/style\.css(\?v=[0-9a-f]+)?"',
    "js/app.js": r'src="js/app\.js(\?v=[0-9a-f]+)?"',
    "js/config.js": r'src="js/config\.js(\?v=[0-9a-f]+)?"',
}


def main() -> int:
    digests = {}
    for rel in ASSETS:
        f = ROOT / rel
        if not f.exists():
            print(f"missing asset: {rel}", file=sys.stderr)
            return 1
        digests[rel] = hashlib.sha1(f.read_bytes()).hexdigest()[:8]

    changed = []
    for page in ROOT.glob("*.html"):
        text = original = page.read_text()
        for rel, pattern in ASSETS.items():
            attr = "href" if rel.endswith(".css") else "src"
            text = re.sub(pattern, f'{attr}="{rel}?v={digests[rel]}"', text)
        if text != original:
            page.write_text(text)
            changed.append(page.name)

    for rel, d in digests.items():
        print(f"  {rel:16} {d}")
    print(f"stamped: {', '.join(changed) if changed else 'no change'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
