import json
import time
from typing import Dict, List, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_TIMEOUT = 25
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 1.5


def build_session() -> requests.Session:
    session = requests.Session()

    retry = Retry(
        total=DEFAULT_RETRIES,
        connect=DEFAULT_RETRIES,
        read=DEFAULT_RETRIES,
        backoff_factor=DEFAULT_BACKOFF,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )

    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) OffensiveReconFramework/3.2"
    })

    return session


def normalize_candidate(candidate: str, domain: str) -> str:
    candidate = candidate.strip().lower().rstrip(".")
    if not candidate:
        return ""
    if "*" in candidate:
        return ""
    if candidate == domain or candidate.endswith(f".{domain}"):
        return candidate
    return ""


def fetch_from_crtsh(session: requests.Session, domain: str, timeout: float) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    results: Set[str] = set()

    for attempt in range(1, DEFAULT_RETRIES + 1):
        try:
            response = session.get(url, timeout=timeout)

            if response.status_code != 200:
                print(f"[!] crt.sh returned HTTP {response.status_code} (attempt {attempt}/{DEFAULT_RETRIES})")
                time.sleep(attempt * 1.5)
                continue

            raw_text = response.text.strip()
            if not raw_text:
                print(f"[!] crt.sh returned empty response (attempt {attempt}/{DEFAULT_RETRIES})")
                time.sleep(attempt * 1.5)
                continue

            try:
                data = response.json()
            except json.JSONDecodeError:
                try:
                    fixed = raw_text.replace("}{", "},{")
                    if not fixed.startswith("["):
                        fixed = f"[{fixed}]"
                    data = json.loads(fixed)
                except Exception:
                    print(f"[!] crt.sh returned invalid JSON (attempt {attempt}/{DEFAULT_RETRIES})")
                    time.sleep(attempt * 1.5)
                    continue

            for entry in data:
                name_value = entry.get("name_value", "")
                for item in name_value.splitlines():
                    normalized = normalize_candidate(item, domain)
                    if normalized:
                        results.add(normalized)

            if results:
                print(f"[+] crt.sh: collected {len(results)} subdomains")
                return results

            print(f"[!] crt.sh returned no usable subdomains (attempt {attempt}/{DEFAULT_RETRIES})")
            time.sleep(attempt * 1.5)

        except requests.exceptions.Timeout:
            print(f"[!] crt.sh timeout on attempt {attempt}/{DEFAULT_RETRIES} for {domain}")
            time.sleep(attempt * 1.5)
        except requests.exceptions.RequestException as exc:
            print(f"[!] crt.sh request failed on attempt {attempt}/{DEFAULT_RETRIES}: {exc}")
            time.sleep(attempt * 1.5)
        except Exception as exc:
            print(f"[!] crt.sh unexpected error on attempt {attempt}/{DEFAULT_RETRIES}: {exc}")
            time.sleep(attempt * 1.5)

    print("[!] crt.sh unavailable, moving to fallback sources")
    return results


def fetch_from_otx(session: requests.Session, domain: str, timeout: float) -> Set[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    results: Set[str] = set()

    for attempt in range(1, DEFAULT_RETRIES + 1):
        try:
            response = session.get(url, timeout=timeout)

            if response.status_code != 200:
                print(f"[!] AlienVault OTX returned HTTP {response.status_code} (attempt {attempt}/{DEFAULT_RETRIES})")
                time.sleep(attempt)
                continue

            data = response.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                normalized = normalize_candidate(hostname, domain)
                if normalized:
                    results.add(normalized)

            if results:
                print(f"[+] AlienVault OTX: collected {len(results)} subdomains")
                return results

            print(f"[!] AlienVault OTX returned no usable subdomains (attempt {attempt}/{DEFAULT_RETRIES})")
            time.sleep(attempt)

        except requests.exceptions.Timeout:
            print(f"[!] AlienVault OTX timeout on attempt {attempt}/{DEFAULT_RETRIES}")
            time.sleep(attempt)
        except requests.exceptions.RequestException as exc:
            print(f"[!] AlienVault OTX request failed on attempt {attempt}/{DEFAULT_RETRIES}: {exc}")
            time.sleep(attempt)
        except Exception as exc:
            print(f"[!] AlienVault OTX unexpected error on attempt {attempt}/{DEFAULT_RETRIES}: {exc}")
            time.sleep(attempt)

    print("[!] AlienVault OTX unavailable, moving to next fallback source")
    return results


def fetch_from_hackertarget(session: requests.Session, domain: str, timeout: float) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    results: Set[str] = set()

    for attempt in range(1, DEFAULT_RETRIES + 1):
        try:
            response = session.get(url, timeout=timeout)

            if response.status_code != 200:
                print(f"[!] HackerTarget returned HTTP {response.status_code} (attempt {attempt}/{DEFAULT_RETRIES})")
                time.sleep(attempt)
                continue

            text = response.text.strip()
            if not text:
                print(f"[!] HackerTarget returned empty response (attempt {attempt}/{DEFAULT_RETRIES})")
                time.sleep(attempt)
                continue

            if "error" in text.lower() or "api count exceeded" in text.lower():
                print(f"[!] HackerTarget rate-limited or errored: {text[:120]}")
                return results

            for line in text.splitlines():
                parts = line.split(",")
                if not parts:
                    continue
                hostname = parts[0].strip()
                normalized = normalize_candidate(hostname, domain)
                if normalized:
                    results.add(normalized)

            if results:
                print(f"[+] HackerTarget: collected {len(results)} subdomains")
                return results

            print(f"[!] HackerTarget returned no usable subdomains (attempt {attempt}/{DEFAULT_RETRIES})")
            time.sleep(attempt)

        except requests.exceptions.Timeout:
            print(f"[!] HackerTarget timeout on attempt {attempt}/{DEFAULT_RETRIES}")
            time.sleep(attempt)
        except requests.exceptions.RequestException as exc:
            print(f"[!] HackerTarget request failed on attempt {attempt}/{DEFAULT_RETRIES}: {exc}")
            time.sleep(attempt)
        except Exception as exc:
            print(f"[!] HackerTarget unexpected error on attempt {attempt}/{DEFAULT_RETRIES}: {exc}")
            time.sleep(attempt)

    print("[!] HackerTarget unavailable")
    return results


def fetch_all_sources(domain: str, timeout: float) -> Dict[str, Set[str]]:
    session = build_session()

    source_results: Dict[str, Set[str]] = {
        "crt.sh": set(),
        "AlienVault OTX": set(),
        "HackerTarget": set(),
    }

    source_results["crt.sh"] = fetch_from_crtsh(session, domain, timeout)
    source_results["AlienVault OTX"] = fetch_from_otx(session, domain, timeout)
    source_results["HackerTarget"] = fetch_from_hackertarget(session, domain, timeout)

    return source_results


def fetch_crtsh_subdomains(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Set[str]:
    """
    Backward-compatible wrapper name.
    Now it queries multiple sources and merges results.
    """
    return fetch_subdomains(domain, timeout)


def fetch_subdomains(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Set[str]:
    merged: Set[str] = set()

    source_results = fetch_all_sources(domain, timeout)

    print("\n[+] Subdomain source summary")
    for source_name, items in source_results.items():
        print(f"    - {source_name}: {len(items)}")

    for items in source_results.values():
        merged.update(items)

    if not merged:
        print("[!] No external subdomains collected from public sources")
    else:
        print(f"[+] Total unique subdomains collected: {len(merged)}")

    return merged
