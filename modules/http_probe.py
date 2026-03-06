from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests


def get_http_title(html: str) -> str:
    lower = html.lower()
    start = lower.find("<title>")
    end = lower.find("</title>")
    if start == -1 or end == -1 or end <= start:
        return ""
    start += len("<title>")
    title = html[start:end].strip()
    return " ".join(title.split())


def probe_url(url: str, timeout: float) -> Optional[Dict]:
    headers = {"User-Agent": "ReconAutomationFramework/3.0"}
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        return {
            "requested_url": url,
            "final_url": r.url,
            "status_code": r.status_code,
            "server": r.headers.get("Server", ""),
            "content_type": r.headers.get("Content-Type", ""),
            "title": get_http_title(r.text[:5000]),
        }
    except requests.RequestException:
        return None


def probe_http_services(
    port_results: Dict[str, List[int]],
    timeout: float,
    threads: int
) -> Dict[str, List[Dict]]:
    results: Dict[str, List[Dict]] = {}
    candidates: List[Tuple[str, str]] = []

    for host, open_ports in port_results.items():
        if 80 in open_ports or 8080 in open_ports:
            candidates.append((host, f"http://{host}"))
        if 443 in open_ports or 8443 in open_ports:
            candidates.append((host, f"https://{host}"))

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(probe_url, url, timeout): (host, url)
            for host, url in candidates
        }

        for future in as_completed(future_map):
            host, _ = future_map[future]
            try:
                result = future.result()
                if not result:
                    continue

                existing = results.setdefault(host, [])
                seen = {item["final_url"] for item in existing}
                if result["final_url"] not in seen:
                    existing.append(result)
            except Exception:
                continue

    return results
