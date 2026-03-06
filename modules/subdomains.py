import json
from typing import Set

import requests


def fetch_crtsh_subdomains(domain: str, timeout: float = 10.0) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "ReconAutomationFramework/3.0"}
    subdomains: Set[str] = set()

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()

        try:
            data = response.json()
        except json.JSONDecodeError:
            return subdomains

        for entry in data:
            name_value = entry.get("name_value", "")
            for item in name_value.splitlines():
                item = item.strip().lower().rstrip(".")
                if not item or "*" in item:
                    continue
                if item == domain or item.endswith(f".{domain}"):
                    subdomains.add(item)

    except requests.RequestException as exc:
        print(f"[!] crt.sh request failed: {exc}")

    return subdomains
