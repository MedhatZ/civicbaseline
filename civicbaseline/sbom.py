from __future__ import annotations

import json
from pathlib import Path

from civicbaseline.models import SoftwareComponent


def load_software_from_sbom(path: Path) -> list[SoftwareComponent]:
    data = json.loads(path.read_text(encoding="utf-8"))
    components: list[SoftwareComponent] = []

    bom_format = (data.get("bomFormat") or "").lower()
    if bom_format == "cyclonedx" or "components" in data:
        vuln_index = _cyclonedx_vuln_index(data)
        for comp in data.get("components") or []:
            name = comp.get("name") or "unknown"
            version = comp.get("version")
            purl = comp.get("purl")
            cves = list(vuln_index.get(comp.get("bom-ref") or name, []))
            for ident in comp.get("evidence", {}).get("identity", []) if isinstance(comp.get("evidence"), dict) else []:
                pass
            components.append(
                SoftwareComponent(
                    name=name,
                    version=version,
                    type=comp.get("type"),
                    purl=purl,
                    cpe=_first_cpe(comp),
                    cves=cves,
                    supplier=_supplier_name(comp),
                )
            )
        # Top-level vulnerabilities without bom-ref still attach by id list
        extra = [v for v in _all_cves(data) if v]
        if extra and components:
            for cve in extra:
                if not any(cve in c.cves for c in components):
                    components[0].cves.append(cve)
        return components

    # SPDX JSON (SPDX-2.3 style)
    for pkg in data.get("packages") or []:
        components.append(
            SoftwareComponent(
                name=pkg.get("name") or "unknown",
                version=pkg.get("versionInfo"),
                purl=_spdx_purl(pkg),
                cves=[],
                supplier=pkg.get("supplier"),
            )
        )
    return components


def _supplier_name(comp: dict) -> str | None:
    supplier = comp.get("supplier")
    if isinstance(supplier, dict):
        return supplier.get("name")
    if isinstance(supplier, str):
        return supplier
    return None


def _first_cpe(comp: dict) -> str | None:
    for item in comp.get("cpe") if isinstance(comp.get("cpe"), list) else [comp.get("cpe")]:
        if item:
            return str(item)
    return None


def _cyclonedx_vuln_index(data: dict) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for vuln in data.get("vulnerabilities") or []:
        cve = vuln.get("id") or ""
        if not str(cve).upper().startswith("CVE-"):
            for ref in vuln.get("references") or []:
                ident = ref.get("id") if isinstance(ref, dict) else None
                if ident and str(ident).upper().startswith("CVE-"):
                    cve = ident
                    break
        if not cve:
            continue
        affects = vuln.get("affects") or []
        if not affects:
            index.setdefault("_all", []).append(cve)
            continue
        for target in affects:
            ref = target.get("ref") if isinstance(target, dict) else str(target)
            index.setdefault(ref, []).append(cve)
    return index


def _all_cves(data: dict) -> list[str]:
    found: list[str] = []
    for vuln in data.get("vulnerabilities") or []:
        ident = vuln.get("id")
        if ident and str(ident).upper().startswith("CVE-"):
            found.append(str(ident).upper())
    return found


def _spdx_purl(pkg: dict) -> str | None:
    for ref in pkg.get("externalRefs") or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None
