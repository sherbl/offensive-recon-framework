import csv
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple

from colorama import Fore, Style, init

init(autoreset=True)


def c(text: str, fg: str, bright: bool = True) -> str:
    style = Style.BRIGHT if bright else ""
    return f"{style}{fg}{text}{Style.RESET_ALL}"


def status_color(code: int) -> str:
    if 200 <= code < 300:
        return c(str(code), Fore.GREEN)
    if 300 <= code < 400:
        return c(str(code), Fore.CYAN)
    if 400 <= code < 500:
        return c(str(code), Fore.YELLOW)
    if 500 <= code < 600:
        return c(str(code), Fore.RED)
    return c(str(code), Fore.WHITE)


def severity_color(level: str) -> str:
    level = level.upper()
    if level == "HIGH":
        return c(level, Fore.RED)
    if level == "MEDIUM":
        return c(level, Fore.YELLOW)
    return c(level, Fore.GREEN)


def section(title: str) -> None:
    line = "═" * 86
    print()
    print(c(line, Fore.RED))
    print(c(f"  {title}", Fore.WHITE))
    print(c(line, Fore.RED))


def subline() -> None:
    print(c("─" * 86, Fore.RED, bright=False))


def kv(label: str, value: str, indent: int = 2) -> None:
    prefix = " " * indent
    print(f"{prefix}{c(label + ':', Fore.CYAN)} {value}")


def bullet(value: str, indent: int = 4, bullet_char: str = "•") -> None:
    prefix = " " * indent
    print(f"{prefix}{c(bullet_char, Fore.RED)} {value}")


def format_list(values: List[str]) -> str:
    return ", ".join(values) if values else "-"


def get_titles(item: Dict) -> str:
    return " | ".join([x.get("title", "") for x in item.get("http", [])]).strip()


def get_titles_lower(item: Dict) -> str:
    return get_titles(item).lower()


def get_http_codes(item: Dict) -> List[int]:
    return [x.get("status_code", 0) for x in item.get("http", [])]


def has_http(item: Dict) -> bool:
    return len(item.get("http", [])) > 0


def infer_role(item: Dict) -> str:
    host = item.get("host", "").lower()
    ports = item.get("open_ports", [])
    titles = get_titles_lower(item)

    if "roundcube" in titles or host.startswith("mail") or host.startswith("smtp") or "mailbox" in host:
        return "Mail Infrastructure"

    if "login" in host or "admin" in host or "panel" in host or "laravel" in titles:
        return "Web Panel"

    if "sandbox" in host or "staging" in host or "dev" in host:
        return "Non-Production / Sandbox"

    if "stream" in host or "vod" in host or "watch" in host:
        return "Streaming / Media"

    if "ads" in host or "adx" in host:
        return "Advertising / Tracking"

    if ports == [21]:
        return "Legacy / FTP-only"

    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        return "Web Infrastructure"

    if 25 in ports or 465 in ports or 587 in ports:
        return "Mail-Exposed Host"

    return "General Infrastructure"


def classify_host(item: Dict) -> List[str]:
    tags = []

    open_ports = item.get("open_ports", [])
    http_entries = item.get("http", [])
    titles = get_titles_lower(item)
    host = item.get("host", "").lower()

    if 21 in open_ports:
        tags.append("FTP")
    if 22 in open_ports:
        tags.append("SSH")
    if 25 in open_ports or 465 in open_ports or 587 in open_ports:
        tags.append("MAIL")
    if 53 in open_ports:
        tags.append("DNS")
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports or 8443 in open_ports:
        tags.append("WEB")

    if "roundcube" in titles:
        tags.append("WEBMAIL")
    if "laravel" in titles:
        tags.append("LARAVEL")
    if "suspended domain" in titles:
        tags.append("SUSPENDED")
    if "login" in titles or "login" in host:
        tags.append("LOGIN")
    if "admin" in titles or "admin" in host:
        tags.append("ADMIN")
    if any(code >= 500 for code in get_http_codes(item)):
        tags.append("HTTP-5XX")
    if any(400 <= code < 500 for code in get_http_codes(item)):
        tags.append("HTTP-4XX")
    if "sandbox" in host or "staging" in host or "dev" in host:
        tags.append("NONPROD")

    return sorted(set(tags))


def score_host(item: Dict) -> Tuple[int, str, List[str]]:
    score = 0
    reasons = []

    host = item.get("host", "").lower()
    ports = item.get("open_ports", [])
    codes = get_http_codes(item)
    titles = get_titles_lower(item)

    if "roundcube" in titles:
        score += 5
        reasons.append("Webmail interface detected")

    if "laravel" in titles:
        score += 4
        reasons.append("Framework login/panel detected")

    if any(code >= 500 for code in codes):
        score += 4
        reasons.append("HTTP 5xx response")

    if any(400 <= code < 500 for code in codes):
        score += 2
        reasons.append("HTTP 4xx response")

    if "login" in titles or "login" in host:
        score += 3
        reasons.append("Login surface")

    if "admin" in titles or "admin" in host:
        score += 3
        reasons.append("Admin-related surface")

    if "sandbox" in host or "staging" in host or "dev" in host:
        score += 3
        reasons.append("Non-production naming")

    if "suspended domain" in titles:
        score += 2
        reasons.append("Suspended / legacy surface")

    if 22 in ports:
        score += 1
        reasons.append("SSH exposed")

    if 21 in ports:
        score += 1
        reasons.append("FTP exposed")

    if 25 in ports or 465 in ports or 587 in ports:
        score += 1
        reasons.append("Mail services exposed")

    if score >= 7:
        return score, "HIGH", reasons
    if score >= 4:
        return score, "MEDIUM", reasons
    return score, "LOW", reasons


def group_by_ip(report: Dict) -> Dict[str, List[Dict]]:
    grouped: Dict[str, List[Dict]] = {}
    for item in report["results"]:
        if not item["resolved"]:
            continue
        ip = item.get("primary_ip") or "-"
        grouped.setdefault(ip, []).append(item)
    return dict(sorted(grouped.items(), key=lambda x: (x[0] == "-", x[0])))


def infer_ip_role(hosts: List[Dict]) -> str:
    names = " ".join([h.get("host", "").lower() for h in hosts])
    titles = " ".join([get_titles_lower(h) for h in hosts])

    if "mail" in names or "smtp" in names or "roundcube" in titles or "mailbox" in names:
        return "Mail Cluster"

    if any("sandbox" in h.get("host", "").lower() or "staging" in h.get("host", "").lower() for h in hosts):
        return "Non-Production Cluster"

    if any("ads" in h.get("host", "").lower() or "adx" in h.get("host", "").lower() for h in hosts):
        return "Advertising / Edge Cluster"

    web_count = sum(
        1 for h in hosts
        if any(p in h.get("open_ports", []) for p in [80, 443, 8080, 8443])
    )
    if web_count >= 2:
        return "Core Web Cluster"

    if all(h.get("open_ports", []) == [21] for h in hosts if h.get("open_ports")):
        return "Legacy FTP Cluster"

    return "Mixed Infrastructure"


def extract_attack_surface(report: Dict) -> Dict[str, List[Dict]]:
    buckets = {
        "web_panels": [],
        "webmail": [],
        "errors_5xx": [],
        "errors_4xx": [],
        "legacy": [],
        "nonprod": [],
    }

    for item in report["results"]:
        titles = get_titles_lower(item)
        host = item.get("host", "").lower()
        codes = get_http_codes(item)

        if "roundcube" in titles:
            buckets["webmail"].append(item)

        if "laravel" in titles or "login" in titles or "admin" in titles:
            buckets["web_panels"].append(item)

        if any(code >= 500 for code in codes):
            buckets["errors_5xx"].append(item)

        if any(400 <= code < 500 for code in codes):
            buckets["errors_4xx"].append(item)

        if "suspended domain" in titles or item.get("open_ports", []) == [21]:
            buckets["legacy"].append(item)

        if "sandbox" in host or "staging" in host or "dev" in host:
            buckets["nonprod"].append(item)

    return buckets


def build_report(
    domain: str,
    subdomains: Set[str],
    resolved: Dict[str, Dict],
    port_results: Dict[str, List[int]],
    http_results: Dict[str, List[Dict]],
) -> Dict:
    entries = []

    for host in sorted(subdomains):
        dns_info = resolved.get(host, {})
        entries.append({
            "host": host,
            "resolved": host in resolved,
            "a_records": dns_info.get("a_records", []),
            "aaaa_records": dns_info.get("aaaa_records", []),
            "cname_records": dns_info.get("cname_records", []),
            "primary_ip": dns_info.get("primary_ip"),
            "open_ports": port_results.get(host, []),
            "http": http_results.get(host, []),
        })

    return {
        "target_domain": domain,
        "stats": {
            "subdomains_found": len(subdomains),
            "resolved_hosts": len(resolved),
            "hosts_with_open_ports": len(port_results),
            "hosts_with_http": len(http_results),
        },
        "results": entries,
    }


def print_executive_summary(report: Dict, grouped: Dict[str, List[Dict]]) -> None:
    stats = report["stats"]

    web_hosts = sum(
        1 for item in report["results"]
        if any(p in item.get("open_ports", []) for p in [80, 443, 8080, 8443])
    )
    mail_hosts = sum(
        1 for item in report["results"]
        if any(p in item.get("open_ports", []) for p in [25, 110, 143, 465, 587])
    )
    ftp_hosts = sum(1 for item in report["results"] if 21 in item.get("open_ports", []))
    ssh_hosts = sum(1 for item in report["results"] if 22 in item.get("open_ports", []))

    scored = [score_host(item) for item in report["results"] if item["resolved"]]
    high_count = sum(1 for _, sev, _ in scored if sev == "HIGH")
    med_count = sum(1 for _, sev, _ in scored if sev == "MEDIUM")

    section("EXECUTIVE SUMMARY")
    kv("Target", report["target_domain"])
    kv("Subdomains discovered", str(stats["subdomains_found"]))
    kv("Resolved hosts", str(stats["resolved_hosts"]))
    kv("Unique infrastructure nodes", str(len(grouped)))
    kv("Web-exposed hosts", str(web_hosts))
    kv("Mail-exposed hosts", str(mail_hosts))
    kv("FTP-exposed hosts", str(ftp_hosts))
    kv("SSH-exposed hosts", str(ssh_hosts))
    kv("High-priority hosts", severity_color(str(high_count)))
    kv("Medium-priority hosts", severity_color(str(med_count)))


def print_attack_surface_map(report: Dict) -> None:
    surface = extract_attack_surface(report)

    section("ATTACK SURFACE MAP")

    print(c("  Web Panels", Fore.WHITE))
    if surface["web_panels"]:
        for item in surface["web_panels"][:10]:
            title = get_titles(item) or "-"
            bullet(f"{item['host']}  ->  {title}", indent=4)
    else:
        bullet("-", indent=4)

    print()
    print(c("  Webmail", Fore.WHITE))
    if surface["webmail"]:
        for item in surface["webmail"][:10]:
            title = get_titles(item) or "-"
            bullet(f"{item['host']}  ->  {title}", indent=4)
    else:
        bullet("-", indent=4)

    print()
    print(c("  Error Responses (5xx)", Fore.WHITE))
    if surface["errors_5xx"]:
        for item in surface["errors_5xx"][:10]:
            bullet(item["host"], indent=4)
    else:
        bullet("-", indent=4)

    print()
    print(c("  Error Responses (4xx)", Fore.WHITE))
    if surface["errors_4xx"]:
        for item in surface["errors_4xx"][:10]:
            bullet(item["host"], indent=4)
    else:
        bullet("-", indent=4)

    print()
    print(c("  Legacy / Suspended / FTP-only", Fore.WHITE))
    if surface["legacy"]:
        for item in surface["legacy"][:10]:
            bullet(item["host"], indent=4)
    else:
        bullet("-", indent=4)

    print()
    print(c("  Non-Production / Sandbox", Fore.WHITE))
    if surface["nonprod"]:
        for item in surface["nonprod"][:10]:
            bullet(item["host"], indent=4)
    else:
        bullet("-", indent=4)


def print_top_findings(report: Dict) -> None:
    ranked = []
    for item in report["results"]:
        if not item["resolved"]:
            continue
        score, severity, reasons = score_host(item)
        ranked.append((score, severity, reasons, item))

    ranked.sort(key=lambda x: x[0], reverse=True)

    section("TOP FINDINGS")

    if not ranked:
        bullet("No resolved findings to rank")
        return

    for score, severity, reasons, item in ranked[:10]:
        print(f"{c('[HOST]', Fore.WHITE)} {c(item['host'], Fore.CYAN)}  "
              f"{c('[SEVERITY]', Fore.WHITE)} {severity_color(severity)}  "
              f"{c('[SCORE]', Fore.WHITE)} {score}")

        kv("Role", infer_role(item), indent=4)
        kv("IP", item.get("primary_ip") or "-", indent=4)

        if item.get("cname_records"):
            kv("CNAME", format_list(item["cname_records"]), indent=4)

        if item.get("open_ports"):
            kv("Ports", ", ".join(map(str, item["open_ports"])), indent=4)

        if item.get("http"):
            for web in item["http"]:
                title = web.get("title", "")
                final_url = web.get("final_url", "-")
                code = web.get("status_code", 0)
                line = f"{final_url} [{status_color(code)}]"
                if title:
                    line += f" | {title}"
                kv("Web", line, indent=4)

        if reasons:
            kv("Why it matters", "; ".join(reasons[:4]), indent=4)

        subline()


def print_hosts_grouped_by_ip(report: Dict, grouped: Dict[str, List[Dict]]) -> None:
    section("INFRASTRUCTURE MAP (GROUPED BY IP)")

    for ip, hosts in grouped.items():
        ip_role = infer_ip_role(hosts)
        print(f"{c('[IP]', Fore.WHITE)} {c(ip, Fore.CYAN)}  "
              f"{c('[ROLE]', Fore.WHITE)} {c(ip_role, Fore.YELLOW)}")

        for item in hosts:
            tags = classify_host(item)
            score, severity, _ = score_host(item)

            tag_str = " ".join([f"[{c(tag, Fore.RED)}]" for tag in tags]) if tags else c("[NO-TAG]", Fore.WHITE)

            print(
                f"  {c('└─', Fore.RED)} {c(item['host'], Fore.CYAN)} "
                f"{tag_str} "
                f"{c('[PRIORITY]', Fore.WHITE)} {severity_color(severity)}"
            )

            if item["cname_records"]:
                kv("CNAME", format_list(item["cname_records"]), indent=6)

            if item["open_ports"]:
                kv("Ports", ", ".join(map(str, item["open_ports"])), indent=6)

            titles = get_titles(item)
            if titles:
                kv("Title", titles, indent=6)

            for web in item["http"]:
                title = web.get("title", "")
                final_url = web.get("final_url", "-")
                code = web.get("status_code", 0)

                line = f"{final_url} [{status_color(code)}]"
                if title:
                    line += f" | {title}"
                kv("Web", line, indent=6)

        subline()


def print_unresolved_hosts(report: Dict) -> None:
    unresolved = [x for x in report["results"] if not x["resolved"]]
    if not unresolved:
        return

    section("UNRESOLVED HOSTS")

    for item in unresolved:
        print(f"{c('[HOST]', Fore.WHITE)} {c(item['host'], Fore.CYAN)}")
        if item["cname_records"]:
            kv("CNAME", format_list(item["cname_records"]), indent=4)
        else:
            kv("CNAME", "-", indent=4)
        subline()


def print_summary(report: Dict) -> None:
    grouped = group_by_ip(report)
    print_executive_summary(report, grouped)
    print_attack_surface_map(report)
    print_top_findings(report)
    print_hosts_grouped_by_ip(report, grouped)
    print_unresolved_hosts(report)


def save_json(report: Dict, path: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def save_csv(report: Dict, path: str) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "host",
            "resolved",
            "primary_ip",
            "role",
            "severity",
            "score",
            "a_records",
            "aaaa_records",
            "cname_records",
            "open_ports",
            "http_urls",
            "http_status_codes",
            "http_titles",
            "tags",
            "reasons",
        ])

        for item in report["results"]:
            score, severity, reasons = score_host(item)
            http_urls = "; ".join([x["final_url"] for x in item["http"]])
            http_codes = "; ".join([str(x["status_code"]) for x in item["http"]])
            http_titles = "; ".join([x["title"] for x in item["http"] if x["title"]])
            tags = ", ".join(classify_host(item))

            writer.writerow([
                item["host"],
                item["resolved"],
                item["primary_ip"] or "",
                infer_role(item),
                severity,
                score,
                ", ".join(item["a_records"]),
                ", ".join(item["aaaa_records"]),
                ", ".join(item["cname_records"]),
                ", ".join(map(str, item["open_ports"])),
                http_urls,
                http_codes,
                http_titles,
                tags,
                "; ".join(reasons),
            ])
