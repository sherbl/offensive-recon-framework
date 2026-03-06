import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List


def scan_single_port(ip: str, port: int, timeout: float) -> bool:
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_host_ports(ip: str, ports: List[int], timeout: float, threads: int) -> List[int]:
    open_ports = []

    with ThreadPoolExecutor(max_workers=min(threads, max(1, len(ports)))) as executor:
        future_map = {
            executor.submit(scan_single_port, ip, port, timeout): port for port in ports
        }
        for future in as_completed(future_map):
            port = future_map[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue

    return sorted(open_ports)


def scan_all_ports(
    resolved_hosts: Dict[str, Dict],
    ports: List[int],
    timeout: float,
    threads: int
) -> Dict[str, List[int]]:
    results: Dict[str, List[int]] = {}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {}
        for host, info in resolved_hosts.items():
            ip = info.get("primary_ip")
            if ip:
                future_map[executor.submit(scan_host_ports, ip, ports, timeout, threads)] = host

        for future in as_completed(future_map):
            host = future_map[future]
            try:
                open_ports = future.result()
                if open_ports:
                    results[host] = open_ports
            except Exception:
                continue

    return results
