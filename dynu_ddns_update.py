#!/usr/bin/env python3
"""
Dynu DDNS updater:
- Finds public IP
- Reads API key + unicodeName from config.ini
- Lists DNS entries via Dynu API
- Updates matching entry with current IPv4 address

Requires: requests
    pip install requests
"""

# 0.1: initial

from __future__ import annotations

import configparser
import ipaddress
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

DYNU_API_BASE = "https://api.dynu.com/v2"
DEFAULT_CONFIG_PATH = "config.ini"


@dataclass(frozen=True)
class DynuConfig:
    api_key: str
    unicode_name: str


class DynuError(RuntimeError):
    pass


def load_config(path: str) -> DynuConfig:
    cfg = configparser.ConfigParser()
    read_files = cfg.read(path)
    if not read_files:
        raise DynuError(f"Config file not found or unreadable: {path}")

    if "dynu" not in cfg:
        raise DynuError(f"Missing [dynu] section in {path}")

    api_key = cfg["dynu"].get("api_key", "").strip()
    unicode_name = cfg["dynu"].get("unicode_name", "").strip()

    if not api_key:
        raise DynuError("Missing dynu.api_key in config.")
    if not unicode_name:
        raise DynuError("Missing dynu.unicode_name in config.")

    return DynuConfig(api_key=api_key, unicode_name=unicode_name)


def get_public_ipv4(timeout: float = 10.0) -> str:
    """
    Uses a public endpoint that returns your IP as plain text.
    If you prefer another service, replace the URL.
    """
    url = "https://api.ipify.org"
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    ip = r.text.strip()

    # Validate IPv4
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        raise DynuError(f"Public IP service returned invalid IP '{ip}': {e}")

    if addr.version != 4:
        raise DynuError(f"Expected IPv4 but got: {ip}")

    return ip


def dynu_headers(api_key: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "API-Key": api_key,
        "Content-Type": "application/json",
        "User-Agent": "dynu-ddns-updater/1.0",
    }


def get_dns_entries(api_key: str, timeout: float = 15.0) -> Dict[str, Any]:
    """
    GET /v2/dns
    Returns JSON like:
      { "statusCode": 200, "domains": [ ... ] }
    """
    url = f"{DYNU_API_BASE}/dns"
    r = requests.get(url, headers=dynu_headers(api_key), timeout=timeout)
    r.raise_for_status()
    return r.json()


def find_entry_by_unicode_name(dns_payload: Dict[str, Any], unicode_name: str) -> Dict[str, Any]:
    # Dynu typically returns "domains" list
    domains = dns_payload.get("domains")
    if not isinstance(domains, list):
        raise DynuError("Unexpected response from Dynu API: missing 'domains' list.")

    matches = [d for d in domains if str(d.get("unicodeName", "")).strip() == unicode_name]
    if not matches:
        available = ", ".join(str(d.get("unicodeName")) for d in domains if d.get("unicodeName"))
        raise DynuError(
            f"No Dynu DNS entry found with unicodeName='{unicode_name}'. "
            f"Available unicodeName values: {available or '(none)'}"
        )

    if len(matches) > 1:
        # Rare, but handle it explicitly
        ids = [m.get("id") for m in matches]
        raise DynuError(f"Multiple entries matched unicodeName='{unicode_name}'. Matching ids={ids}")

    return matches[0]


def update_dns_entry_ipv4(api_key: str, entry: Dict[str, Any], new_ipv4: str, timeout: float = 15.0) -> Dict[str, Any]:
    """
    Dynu update is typically:
      POST /v2/dns/{id}
    with body containing the domain object.
    We'll send back the object, updating ipv4Address.
    """
    entry_id = entry.get("id")
    if entry_id is None:
        raise DynuError("Selected entry has no 'id' field; cannot update.")

    # Prepare payload: start with the entry object and update ipv4Address
    payload = dict(entry)
    payload["ipv4Address"] = new_ipv4

    url = f"{DYNU_API_BASE}/dns/{entry_id}"
    r = requests.post(url, headers=dynu_headers(api_key), json=payload, timeout=timeout)
    r.raise_for_status()
    return r.json()


def main() -> int:
    config_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CONFIG_PATH

    try:
        cfg = load_config(config_path)
        public_ip = get_public_ipv4()
        dns_payload = get_dns_entries(cfg.api_key)
        entry = find_entry_by_unicode_name(dns_payload, cfg.unicode_name)

        current_ip = str(entry.get("ipv4Address", "")).strip()
        if current_ip == public_ip:
            print(f"No update needed: {cfg.unicode_name} already set to {public_ip}")
            return 0

        result = update_dns_entry_ipv4(cfg.api_key, entry, public_ip)
        print(f"Updated {cfg.unicode_name}: {current_ip or '(none)'} -> {public_ip}")
        # Optional: print a tiny bit of returned info
        if isinstance(result, dict) and "statusCode" in result:
            print(f"Dynu API statusCode: {result.get('statusCode')}")
        return 0

    except requests.HTTPError as e:
        # Include response body if present (helps debugging)
        resp = getattr(e, "response", None)
        body = ""
        if resp is not None:
            try:
                body = resp.text
            except Exception:
                body = ""
        print(f"HTTP error: {e}\n{body}".strip(), file=sys.stderr)
        return 2
    except (requests.RequestException, DynuError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
