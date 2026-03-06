from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

import dns.resolver


def dns_query(hostname: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(hostname, record_type, lifetime=3.0)
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


def resolve_host(hostname: str) -> Optional[Dict]:
    a_records = dns_query(hostname, "A")
    aaaa_records = dns_query(hostname, "AAAA")
    cname_records = dns_query(hostname, "CNAME")

    if not a_records and not aaaa_records and not cname_records:
        return None

    primary_ip = a_records[0] if a_records else (aaaa_records[0] if aaaa_records else None)

    return {
        "host": hostname,
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "cname_records": cname_records,
        "primary_ip": primary_ip,
    }


def resolve_subdomains(subdomains: List[str], threads: int) -> Dict[str, Dict]:
    resolved: Dict[str, Dict] = {}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {executor.submit(resolve_host, sub): sub for sub in subdomains}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                result = future.result()
                if result:
                    resolved[host] = result
            except Exception:
                continue

    return resolved
