from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from civicbaseline.models import (
    Account,
    Asset,
    EvidenceBundle,
    FirewallRule,
    Policies,
    SoftwareComponent,
)
from civicbaseline.pcap import load_pcap_flows
from civicbaseline.sbom import load_software_from_sbom


EVIDENCE_FILES = (
    "inventory.yaml",
    "firewall.yaml",
    "accounts.yaml",
    "policies.yaml",
    "zones.yaml",
    "software.yaml",
)


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def load_evidence(evidence_dir: str | Path, kev_cves: set[str] | None = None) -> EvidenceBundle:
    root = Path(evidence_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Evidence directory not found: {root}")

    inventory = _read_yaml(root / "inventory.yaml")
    firewall = _read_yaml(root / "firewall.yaml")
    accounts = _read_yaml(root / "accounts.yaml")
    policies_raw = _read_yaml(root / "policies.yaml")
    zones = _read_yaml(root / "zones.yaml")
    software_raw = _read_yaml(root / "software.yaml")

    assets = [Asset.model_validate(item) for item in inventory.get("assets", [])]
    rules = [FirewallRule.model_validate(item) for item in firewall.get("rules", [])]
    accts = [Account.model_validate(item) for item in accounts.get("accounts", [])]
    policies = Policies.model_validate(policies_raw) if policies_raw else Policies()
    ip_zones = {str(k): str(v) for k, v in (zones.get("ip_zones") or {}).items()}

    software: list[SoftwareComponent] = []
    sbom_present = False
    for item in software_raw.get("components", []):
        software.append(SoftwareComponent.model_validate(item))

    for sbom_name in ("sbom.json", "bom.json", "sbom.cdx.json"):
        sbom_path = root / sbom_name
        if sbom_path.exists():
            sbom_present = True
            software.extend(load_software_from_sbom(sbom_path))

    if software and not sbom_present:
        # A hand-built software.yaml still counts as a partial inventory, not a real SBOM.
        sbom_present = bool(software_raw.get("is_sbom"))

    pcap_flows = []
    for candidate in sorted(root.glob("*.pcap")) + sorted(root.glob("pcap/*.pcap")):
        pcap_flows.extend(load_pcap_flows(candidate, ip_zones))

    org = inventory.get("organization") or policies_raw.get("organization") or root.name
    sector = inventory.get("sector") or "water"

    return EvidenceBundle(
        organization=org,
        sector=sector,
        assets=assets,
        firewall_rules=rules,
        accounts=accts,
        policies=policies,
        ip_zones=ip_zones,
        software=software,
        sbom_present=sbom_present,
        pcap_flows=pcap_flows,
        kev_cves=kev_cves or set(),
    )
