from __future__ import annotations

import json
import urllib.request
from pathlib import Path

DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def bundled_kev_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "kev-sample.json"


def load_kev_cves(
    path: str | Path | None = None,
    fetch: bool = False,
    url: str = DEFAULT_KEV_URL,
    timeout: int = 20,
) -> set[str]:
    """Return a set of CVE IDs from a local KEV JSON or the bundled sample.

    When fetch=True the official CISA feed is downloaded. CivicBaseline stores
    identifiers only — never exploit steps.
    """
    if fetch:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — URL is pinned default
            payload = json.loads(resp.read().decode("utf-8"))
        return _extract_cves(payload)

    kev_file = Path(path) if path else bundled_kev_path()
    if not kev_file.exists():
        return set()
    payload = json.loads(kev_file.read_text(encoding="utf-8"))
    return _extract_cves(payload)


def _extract_cves(payload: dict) -> set[str]:
    cves: set[str] = set()
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cveID") or item.get("cve") or item.get("id")
        if cve:
            cves.add(str(cve).upper())
    return cves
