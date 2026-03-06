from typing import List


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        raise ValueError("Pass a domain only, not a URL")
    return domain.rstrip(".")


def parse_ports(raw_ports: str) -> List[int]:
    ports = []
    for item in raw_ports.split(","):
        item = item.strip()
        if not item:
            continue
        port = int(item)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")
        ports.append(port)
    return sorted(set(ports))
