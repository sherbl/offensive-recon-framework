#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

import requests

from modules.banner import print_banner
from modules.http_probe import probe_http_services
from modules.reporter import build_report, print_summary, save_json, save_csv
from modules.resolver import resolve_subdomains
from modules.scanner import scan_all_ports
from modules.subdomains import fetch_crtsh_subdomains
from modules.utils import normalize_domain, parse_ports

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 8080, 8443]
DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 30


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recon Automation Framework v3 - authorized security testing only"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target root domain")
    parser.add_argument("-o", "--output", default="output/output.json", help="Output JSON path")
    parser.add_argument("--csv", default="output/output.csv", help="Output CSV path")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Worker threads")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Network timeout")
    parser.add_argument(
        "--ports",
        default=",".join(map(str, COMMON_PORTS)),
        help="Comma-separated TCP ports"
    )
    return parser.parse_args()


def main() -> int:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    args = parse_args()

    try:
        domain = normalize_domain(args.domain)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"[!] Input error: {exc}")
        return 1

    print_banner()

    print(f"[+] Target   : {domain}")
    print(f"[+] Threads  : {args.threads}")
    print(f"[+] Timeout  : {args.timeout}")
    print(f"[+] Ports    : {ports}")
    print("[+] Starting reconnaissance...\n")

    subdomains = fetch_crtsh_subdomains(domain)
    subdomains.add(domain)
    subdomains.add(f"www.{domain}")

    print(f"[+] Discovered {len(subdomains)} candidate hosts")

    resolved = resolve_subdomains(sorted(subdomains), args.threads)
    print(f"[+] Resolved {len(resolved)} hosts")

    port_results = scan_all_ports(
        resolved_hosts=resolved,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
    )
    print(f"[+] Port scan completed")

    http_results = probe_http_services(
        port_results=port_results,
        timeout=args.timeout,
        threads=args.threads,
    )
    print(f"[+] HTTP probing completed")

    report = build_report(
        domain=domain,
        subdomains=subdomains,
        resolved=resolved,
        port_results=port_results,
        http_results=http_results,
    )

    Path("output").mkdir(exist_ok=True)

    save_json(report, args.output)
    save_csv(report, args.csv)

    print_summary(report)

    print(f"[+] JSON saved to: {Path(args.output).resolve()}")
    print(f"[+] CSV  saved to: {Path(args.csv).resolve()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
