import argparse
import json
import os
import subprocess
import shlex
import sys

USE_MCP = False
MCP_CMD = "mcp"

def parse_args():
    parser = argparse.ArgumentParser(description="Check whether an Ollama instance is exposed.")
    parser.add_argument("--scan-cidr", help="CIDR block to scan (e.g. 10.0.0.0/8).")
    parser.add_argument("--use-mcp", action="store_true", help="Run the check via the MCP browser‑bridge instead of a direct HTTP request.")
    parser.add_argument("--mcp-cmd", default=MCP_CMD, help="Path to the MCP executable (default: %(default)s).")
    parser.add_argument("--output-json", help="Write JSON results here.")
    return parser.parse_args()

def run_mcp_check(ip: str, mcp_exe: str) -> dict:
    url = f"http://{ip}:11434/api/ps"
    cmd = [mcp_exe, "run", url, "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        print(f"[!] MCP executable not found: {mcp_exe}", file=sys.stderr)
        return {"ip": ip, "exposed": False, "models": []}
    except subprocess.TimeoutExpired:
        print(f"[!] MCP timed out while checking {ip}", file=sys.stderr)
        return {"ip": ip, "exposed": False, "models": []}
    if result.returncode != 0:
        print(f"[!] MCP returned error for {ip}: {result.stderr}", file=sys.stderr)
        return {"ip": ip, "exposed": False, "models": []}
    try:
        data = json.loads(result.stdout)
        models = data.get("models", []) if isinstance(data, dict) else []
        return {"ip": ip, "exposed": True, "models": models}
    except json.JSONDecodeError:
        print(f"[!] Could not decode MCP JSON for {ip}", file=sys.stderr)
        return {"ip": ip, "exposed": False, "models": []}

def probe(ip: str) -> dict:
    global USE_MCP, MCP_CMD
    if USE_MCP:
        return run_mcp_check(ip, MCP_CMD)
    else:
        try:
            import requests
            resp = requests.get(f"http://{ip}:11434/api/ps", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                models = data.get("models", []) if isinstance(data, dict) else []
                return {"ip": ip, "exposed": True, "models": models}
        except Exception:
            pass
        return {"ip": ip, "exposed": False, "models": []}

def scan_cidr(cidr: str, timeout: int = 5):
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor, as_completed

    net = ipaddress.ip_network(cidr, strict=False)
    live = []

    def probe_ip(ip):
        return probe(ip)

    with ThreadPoolExecutor(max_workers=200) as pool:
        futures = {pool.submit(probe_ip, str(ip)): ip for ip in net.hosts()}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                live.append(res)
    return live

def main():
    args = parse_args()

    # Determine CIDR
    if args.scan_cidr:
        cidr_to_scan = args.scan_cidr
    else:
        cidr_to_scan = os.getenv("CIDR")
        if not cidr_to_scan:
            raise SystemExit("Either --scan-cidr or CIDR env‑var required")

    # Choose backend (direct HTTP vs MCP)
    global USE_MCP
    if args.use_mcp:
        USE_MCP = True
        MCP_CMD = args.mcp_cmd

    hits = scan_cidr(cidr_to_scan)

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(hits, f, indent=2)
    else:
        print(json.dumps(hits, indent=2))

if __name__ == "__main__":
    main()