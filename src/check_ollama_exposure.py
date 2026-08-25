#!/usr/bin/env python3
"""
LeakyCompute defensive CLI — audit YOUR infrastructure only.

Modes:
  --check-url URL     Probe a single Ollama base URL (GET /api/ps only)
  --scan-local        Scan common AI ports on localhost
  --scan-cidr CIDR    Scan a CIDR you own (requires --i-own-this-range)
  --demo-local        Local Docker path-traversal demo (localhost-bound)
  --output-json PATH  Write machine-readable results

Never use against systems without authorization.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib import error, request

DEFAULT_PORT = 11434
AI_PORTS = [
    (8000, "vLLM / FastAPI"),
    (11434, "Ollama"),
    (5000, "HuggingFace TGI"),
    (7497, "LMStudio"),
    (8080, "common API"),
]
DOCKER_IMAGE = "ollama/ollama:latest"
DEMO_NAME = "ollama-poc-demo"
MAX_HTTP_BODY = 32 * 1024


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = request.build_opener(_NoRedirect)


def validate_base_url(url: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must use http(s) and include a host")
    if parsed.username or parsed.password:
        raise ValueError("credentials in URLs are not accepted")
    return url.rstrip("/")


def is_loopback_url(url: str) -> bool:
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(host, None)}
        return bool(addresses) and all(ipaddress.ip_address(ip).is_loopback for ip in addresses)
    except (OSError, ValueError):
        return False


def http_json(url: str, method: str = "GET", data: dict | None = None, timeout: float = 5.0):
    body = json.dumps(data).encode() if data is not None else None
    req = request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", "User-Agent": "LeakyCompute-CLI/1.0"},
    )
    try:
        with HTTP.open(req, timeout=timeout) as resp:
            body_bytes = resp.read(MAX_HTTP_BODY + 1)
            if len(body_bytes) > MAX_HTTP_BODY:
                raise ValueError("response_too_large")
            raw = body_bytes.decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except error.HTTPError as e:
        body_bytes = e.read(MAX_HTTP_BODY + 1) if e.fp else b""
        raw = (
            "response_too_large"
            if len(body_bytes) > MAX_HTTP_BODY
            else body_bytes.decode("utf-8", errors="replace")
        )
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return None, str(e)


def probe_ollama(base: str, timeout: float = 3.0) -> dict[str, Any]:
    base = validate_base_url(base)
    status, payload = http_json(f"{base}/api/ps", timeout=timeout)
    if status == 200 and isinstance(payload, dict):
        models = payload.get("models") or []
        return {
            "url": base,
            "exposed": True,
            "status": status,
            "models": [
                {"name": m.get("name") or m.get("model"), "size": m.get("size")}
                for m in models[:25]
            ],
        }
    if status in (401, 403):
        return {"url": base, "exposed": False, "auth_required": True, "status": status, "models": []}
    return {
        "url": base,
        "exposed": False,
        "status": status,
        "models": [],
        "error": payload if status is None else None,
    }


def scan_local(host: str = "127.0.0.1") -> list[dict]:
    found = []
    for port, desc in AI_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        open_ = sock.connect_ex((host, port)) == 0
        sock.close()
        if not open_:
            continue
        row = {"host": host, "port": port, "desc": desc}
        if port == DEFAULT_PORT:
            row["probe"] = probe_ollama(f"http://{host}:{port}")
        found.append(row)
    return found


def scan_cidr(cidr: str, port: int, max_hosts: int, workers: int, timeout: float) -> list[dict]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
    if len(hosts) > max_hosts:
        raise SystemExit(
            f"CIDR expands to {len(hosts)} hosts; max allowed is {max_hosts}. "
            "Narrow the range or raise --max-hosts deliberately."
        )
    results: list[dict] = []

    def one(ip: str):
        return probe_ollama(f"http://{ip}:{port}", timeout=timeout)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futs = {pool.submit(one, str(ip)): str(ip) for ip in hosts}
        for fut in as_completed(futs):
            results.append(fut.result())
    return results


def demo_local():
    print("Starting localhost-only Docker demo (port 14000)…")
    try:
        subprocess.run(["docker", "version"], capture_output=True, check=True, timeout=10)
    except Exception:
        print("Docker not available.", file=sys.stderr)
        return 1
    subprocess.run(["docker", "rm", "-f", DEMO_NAME], capture_output=True)
    r = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            DEMO_NAME,
            "-p",
            "127.0.0.1:14000:11434",
            DOCKER_IMAGE,
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        return 1
    try:
        for _ in range(30):
            st, _ = http_json("http://127.0.0.1:14000/api/ps", timeout=2)
            if st == 200:
                break
            time.sleep(1)
        else:
            print("Ollama did not become ready.", file=sys.stderr)
            return 1
        secret = "SECRET_TOKEN=poc_demo_value_12345\n"
        subprocess.run(
            ["docker", "exec", DEMO_NAME, "sh", "-c", f"printf '%s' '{secret}' > /tmp/ollama_poc_test_secret.txt"],
            check=False,
        )
        print("Container ready. Exposure probe:")
        print(json.dumps(probe_ollama("http://127.0.0.1:14000"), indent=2))
        print(
            "\nPath-traversal demos against third-party hosts are intentionally not automated.\n"
            "Use this container only on localhost to study model-name handling safely."
        )
        return 0
    finally:
        subprocess.run(["docker", "rm", "-f", DEMO_NAME], capture_output=True)


def main():
    p = argparse.ArgumentParser(description="LeakyCompute defensive Ollama exposure CLI")
    p.add_argument("--check-url", help="Base URL e.g. http://127.0.0.1:11434")
    p.add_argument("--scan-local", action="store_true")
    p.add_argument("--scan-cidr", help="CIDR you own, e.g. 203.0.113.0/28")
    p.add_argument(
        "--i-own-this-range",
        action="store_true",
        help="Required with --scan-cidr; attests authorization",
    )
    p.add_argument(
        "--i-own-this-host",
        action="store_true",
        help="Required with a non-loopback --check-url; attests authorization",
    )
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--max-hosts", type=int, default=256)
    p.add_argument("--workers", type=int, default=32)
    p.add_argument("--timeout", type=float, default=3.0)
    p.add_argument("--demo-local", action="store_true")
    p.add_argument("--output-json", help="Write results JSON to path")
    args = p.parse_args()

    out: Any = None
    if args.demo_local:
        return demo_local()
    if args.check_url:
        validated = validate_base_url(args.check_url)
        if not is_loopback_url(validated) and not args.i_own_this_host:
            raise SystemExit("Refusing non-loopback --check-url without --i-own-this-host")
        out = probe_ollama(validated, timeout=args.timeout)
    elif args.scan_local:
        out = scan_local()
    elif args.scan_cidr:
        if not args.i_own_this_range:
            raise SystemExit("Refusing CIDR scan without --i-own-this-range")
        out = scan_cidr(args.scan_cidr, args.port, args.max_hosts, args.workers, args.timeout)
    else:
        p.print_help()
        return 2

    text = json.dumps(out, indent=2)
    print(text)
    if args.output_json:
        with open(args.output_json, "w") as f:
            f.write(text)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
