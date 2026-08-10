#!/usr/bin/env python3
"""
Favicon hash generator for search-engine pivots.

Why this exists
---------------
Port/title queries miss any instance behind a reverse proxy on 443, on a
non-standard port, or with a localized page title. Favicon hashes don't care
about any of that — they match the served icon bytes.

Do NOT copy favicon hashes out of blog posts. They drift between releases and
a stale hash silently returns zero results, which reads like "no exposure"
rather than "wrong query". Generate them from a version you ran yourself.

Two hash formats, because the engines disagree:
  * Shodan  -> mmh3(base64.encodebytes(icon))  32-bit signed  -> http.favicon.hash:
  * Censys  -> md5(icon) hex                                  -> favicon md5 field
  * Netlas / others generally accept md5 or sha256.

Stdlib only (repo convention) — MurmurHash3 x86_32 is implemented below.

Usage
-----
  # From a local container you control (the recommended path):
  python3 scripts/discovery/favicon_hash.py http://127.0.0.1:8888

  # Several at once, emitting YAML ready to paste into profiles.yaml:
  python3 scripts/discovery/favicon_hash.py --yaml \
      jupyter=http://127.0.0.1:8888 comfyui=http://127.0.0.1:8188

  # From an icon already on disk:
  python3 scripts/discovery/favicon_hash.py --file ./favicon.ico
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import urllib.error
import urllib.parse
import urllib.request

class _InlineFavicon(RuntimeError):
    """Icon is embedded in the page, so there is nothing an engine can index."""


USER_AGENT = "LeakyCompute-FaviconHash/1.0 (+defensive research; single GET)"
TIMEOUT = 8


# --- MurmurHash3 x86_32 (Shodan's favicon hash) ----------------------------
def murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xFFFFFFFC

    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | (data[i + 3] << 24)
        ) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if tail >= 1:
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1


def to_signed32(v: int) -> int:
    return v - 0x100000000 if v >= 0x80000000 else v


def shodan_favicon_hash(icon: bytes) -> int:
    """Shodan hashes the base64 encoding *with* line breaks (encodebytes)."""
    return to_signed32(murmur3_32(base64.encodebytes(icon)))


# --- fetching ---------------------------------------------------------------
def fetch_favicon(base_url: str) -> tuple[bytes, str]:
    """
    Single read-only GET for the icon. Tries /favicon.ico, then the
    <link rel="icon"> declared on the root page.
    """
    base = base_url.rstrip("/")
    candidates = [f"{base}/favicon.ico"]

    try:
        root = _get(base)
        href = _icon_href(root.decode("utf-8", "replace"))
        if href:
            # urljoin handles './x', '../x', '/x', '//host/x' and absolute URLs.
            # Hand-rolled prefixing gets './static-files/favicon.ico' wrong,
            # which is exactly what MLflow serves.
            joined = urllib.parse.urljoin(base + "/", href)
            # A data: URI means the icon is inlined in the HTML and there is no
            # fetchable favicon resource. Search engines hash the HTTP response
            # for the icon, so an inlined icon CANNOT be used as a pivot —
            # hashing it would produce a value that never matches anything.
            if joined.lower().startswith("data:"):
                raise _InlineFavicon(
                    "favicon is inlined as a data: URI — not usable as a "
                    "search-engine pivot for this service"
                )
            candidates.append(joined)
    except _InlineFavicon:
        raise
    except Exception:
        pass

    last = ""
    for url in candidates:
        try:
            data = _get(url)
            if data:
                return data, url
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
    raise RuntimeError(f"no favicon found (last error: {last or 'none'})")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
        return resp.read(1_000_000)


def _icon_href(html: str) -> str | None:
    import re

    m = re.search(
        r"""<link[^>]+rel=["'][^"']*\bicon\b[^"']*["'][^>]*>""", html, re.I
    )
    if not m:
        return None
    h = re.search(r"""href=["']([^"']+)["']""", m.group(0), re.I)
    return h.group(1) if h else None


def report(label: str, icon: bytes, src: str) -> dict:
    sh = shodan_favicon_hash(icon)
    md5 = hashlib.md5(icon).hexdigest()  # noqa: S324 - fingerprint, not crypto
    sha256 = hashlib.sha256(icon).hexdigest()
    return {
        "label": label,
        "source": src,
        "bytes": len(icon),
        "shodan_mmh3": sh,
        "md5": md5,
        "sha256": sha256,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("targets", nargs="*", help="URL or label=URL")
    ap.add_argument("--file", help="hash an icon file instead of fetching")
    ap.add_argument("--yaml", action="store_true", help="emit profiles.yaml-shaped output")
    ap.add_argument("--selftest", action="store_true", help="verify the mmh3 implementation")
    args = ap.parse_args()

    if args.selftest:
        vectors = {b"": 0, b"foo": -156908512, b"hello": 613153351}
        ok = True
        for data, want in vectors.items():
            got = to_signed32(murmur3_32(data))
            status = "ok  " if got == want else "FAIL"
            if got != want:
                ok = False
            print(f"  {status} murmur3_32({data!r}) = {got} (want {want})")
        print("selftest passed" if ok else "SELFTEST FAILED")
        return 0 if ok else 1

    rows = []
    if args.file:
        with open(args.file, "rb") as fh:
            rows.append(report(args.file, fh.read(), args.file))
    for t in args.targets:
        label, _, url = t.partition("=")
        if not url:
            label, url = url or t, t
        try:
            icon, src = fetch_favicon(url)
            rows.append(report(label or url, icon, src))
        except Exception as exc:  # noqa: BLE001
            print(f"[!] {label or url}: {exc}", file=sys.stderr)

    if not rows:
        ap.print_help()
        return 1

    if args.yaml:
        print("# paste under the relevant profile in profiles.yaml")
        for r in rows:
            print(f"  # {r['label']}: {r['bytes']} bytes from {r['source']}")
            print("  favicon:")
            print(f"    shodan_mmh3: {r['shodan_mmh3']}")
            print(f"    md5: {r['md5']}")
            print(f"    generated_from: \"{r['source']}\"")
    else:
        for r in rows:
            print(f"\n{r['label']}  ({r['bytes']} bytes from {r['source']})")
            print(f"  Shodan : http.favicon.hash:{r['shodan_mmh3']}")
            print(f"  Censys : {r['md5']}  (md5)")
            print(f"  sha256 : {r['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
