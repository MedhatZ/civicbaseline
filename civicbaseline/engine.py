from __future__ import annotations

from typing import Any, Iterable

from civicbaseline.models import (
    Asset,
    CheckResult,
    CheckSpec,
    EvidenceBundle,
    FirewallRule,
    RuleResult,
    RuleSpec,
    Status,
)
from civicbaseline.scoring import ot_weight_for_assets, priority_score, rollup_status


def assess(rules: list[RuleSpec], evidence: EvidenceBundle) -> list[RuleResult]:
    results: list[RuleResult] = []
    for rule in rules:
        check_results: list[CheckResult] = []
        failed_assets: list[str] = []
        for check in rule.checks:
            result = evaluate_check(check, evidence)
            check_results.append(result)
            failed_assets.extend(_asset_ids_from_message(result))
        status = rollup_status([c.status for c in check_results])
        assets = _matching_assets(rule, evidence)
        weight = rule.ot_weight * ot_weight_for_assets(assets)
        results.append(
            RuleResult(
                rule=rule,
                status=status,
                checks=check_results,
                score_weight=weight,
                priority=priority_score(rule, status, weight),
                failed_assets=sorted(set(failed_assets)),
            )
        )
    return results


def evaluate_check(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    dispatch = {
        "asset_field": _check_asset_field,
        "inventory_quality": _check_inventory_quality,
        "inventory_min_count": _check_inventory_min_count,
        "policy_true": _check_policy_true,
        "segmentation": _check_segmentation,
        "no_internet_to_ot": _check_no_internet_to_ot,
        "accounts_field": _check_accounts_field,
        "sbom_present": _check_sbom_present,
        "kev_match": _check_kev_match,
        "pcap_cleartext": _check_pcap_cleartext,
        "pcap_cross_zone": _check_pcap_cross_zone,
        "software_inventory_present": _check_software_inventory,
    }
    handler = dispatch.get(check.type)
    if handler is None:
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message=f"Unsupported check type '{check.type}'",
        )
    return handler(check, evidence)


def _where_match(asset: Asset, where: dict[str, Any]) -> bool:
    if not where:
        return True
    type_in = where.get("type_in")
    if type_in and asset.type not in type_in:
        return False
    zone_in = where.get("zone_in")
    if zone_in and asset.zone not in zone_in:
        return False
    if "remote_access" in where and asset.remote_access != bool(where["remote_access"]):
        return False
    if "internet_exposed" in where and asset.internet_exposed != bool(where["internet_exposed"]):
        return False
    if "managed_by_msp" in where and asset.managed_by_msp != bool(where["managed_by_msp"]):
        return False
    return True


def _check_asset_field(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    field = check.field
    if not field:
        return CheckResult(check_id=check.id, status=Status.unknown, message="Missing field")
    matched = [a for a in evidence.assets if _where_match(a, check.where)]
    if not matched:
        if check.unknown_if_empty or check.where:
            return CheckResult(
                check_id=check.id,
                status=Status.not_applicable,
                message="No assets in scope for this check",
            )
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=check.fail_message or "Asset inventory is empty",
        )
    offenders: list[Asset] = []
    unknowns: list[Asset] = []
    for asset in matched:
        value = getattr(asset, field, None)
        if value is None:
            unknowns.append(asset)
            continue
        if value != check.expected:
            offenders.append(asset)
    if offenders:
        refs = [a.id for a in offenders]
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or f"Field {field} did not match {check.expected}")
            + ": "
            + ", ".join(refs),
            evidence_refs=refs,
        )
    if unknowns:
        refs = [a.id for a in unknowns]
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message=f"No evidence for '{field}' on: " + ", ".join(refs),
            evidence_refs=refs,
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message=f"All {len(matched)} in-scope assets satisfy {field}={check.expected}",
        evidence_refs=[a.id for a in matched],
    )


def _check_inventory_quality(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if not evidence.assets:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=check.fail_message or "No asset inventory provided",
        )
    required = check.required_fields or ["zone", "firmware", "owner", "criticality"]
    incomplete: list[str] = []
    for asset in evidence.assets:
        missing = []
        for field in required:
            value = getattr(asset, field, None)
            if value is None or value == "" or value == "unknown":
                missing.append(field)
        if missing:
            incomplete.append(f"{asset.id} (missing {', '.join(missing)})")
    if incomplete:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or "Inventory is incomplete") + ": " + "; ".join(incomplete[:12]),
            evidence_refs=[row.split(" ")[0] for row in incomplete],
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message=f"Inventory of {len(evidence.assets)} assets includes {', '.join(required)}",
    )


def _check_inventory_min_count(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    minimum = int(check.expected or 1)
    count = len(evidence.assets)
    if count >= minimum:
        return CheckResult(
            check_id=check.id,
            status=Status.pass_,
            message=f"Inventory contains {count} assets (minimum {minimum})",
        )
    return CheckResult(
        check_id=check.id,
        status=Status.fail,
        message=check.fail_message or f"Inventory has {count} assets; expected at least {minimum}",
    )


def _dig(obj: Any, dotted: str) -> Any:
    current = obj
    for part in dotted.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def _check_policy_true(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    field = check.field
    if not field:
        return CheckResult(check_id=check.id, status=Status.unknown, message="Missing policy field")
    value = _dig(evidence.policies, field)
    if value is True:
        return CheckResult(check_id=check.id, status=Status.pass_, message=f"Policy {field} is true")
    if value is False:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=check.fail_message or f"Policy {field} is not implemented",
        )
    return CheckResult(
        check_id=check.id,
        status=Status.unknown,
        message=f"Policy {field} not evidenced",
    )


def _active_rules(evidence: EvidenceBundle) -> Iterable[FirewallRule]:
    return [r for r in evidence.firewall_rules if r.enabled and r.action.lower() == "allow"]


def _check_segmentation(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if not evidence.firewall_rules:
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message="No firewall evidence provided",
        )
    forbidden = {tuple(pair) for pair in check.forbid_pairs}
    hits: list[str] = []
    for rule in _active_rules(evidence):
        pair = (rule.src_zone, rule.dst_zone)
        if pair in forbidden or (rule.src_zone, rule.dst_zone) in {(a, b) for a, b in forbidden}:
            hits.append(f"{rule.id} {rule.src_zone}->{rule.dst_zone}/{rule.service}")
        if pair[0] == "any" or pair[1] == "any":
            for src, dst in forbidden:
                if (rule.src_zone in {src, "any"} and rule.dst_zone in {dst, "any"}):
                    hits.append(f"{rule.id} overly broad {rule.src_zone}->{rule.dst_zone}")
    if hits:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or "Forbidden zone conduits exist") + ": " + "; ".join(hits),
            evidence_refs=hits,
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message="No forbidden zone pairs in enabled allow rules",
    )


def _check_no_internet_to_ot(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if not evidence.firewall_rules:
        exposed = [a.id for a in evidence.assets if a.internet_exposed and a.zone in {"ot", "control", "safety"}]
        if exposed:
            return CheckResult(
                check_id=check.id,
                status=Status.fail,
                message=(check.fail_message or "OT assets marked internet-exposed") + ": " + ", ".join(exposed),
                evidence_refs=exposed,
            )
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message="No firewall evidence and no internet-exposed OT flags",
        )
    spec = CheckSpec(
        id=check.id,
        type="segmentation",
        forbid_pairs=check.forbid_pairs or [["internet", "ot"], ["it", "ot"], ["any", "ot"]],
        fail_message=check.fail_message,
    )
    return _check_segmentation(spec, evidence)


def _check_accounts_field(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    field = check.field
    if not field:
        return CheckResult(check_id=check.id, status=Status.unknown, message="Missing account field")
    if not evidence.accounts:
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message="No account evidence provided",
        )
    offenders = []
    for acct in evidence.accounts:
        if acct.disabled:
            continue
        value = getattr(acct, field, None)
        if value != check.expected:
            offenders.append(acct.id)
    if offenders:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or f"Accounts fail {field}={check.expected}") + ": " + ", ".join(offenders),
            evidence_refs=offenders,
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message=f"All active accounts satisfy {field}={check.expected}",
    )


def _check_sbom_present(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if evidence.sbom_present:
        return CheckResult(
            check_id=check.id,
            status=Status.pass_,
            message=f"SBOM present with {len(evidence.software)} components",
        )
    if evidence.software:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=check.fail_message
            or "Software list found but not a machine-readable SBOM (CycloneDX/SPDX)",
        )
    return CheckResult(
        check_id=check.id,
        status=Status.fail,
        message=check.fail_message or "No SBOM or software inventory provided",
    )


def _check_software_inventory(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if evidence.software or evidence.sbom_present:
        return CheckResult(
            check_id=check.id,
            status=Status.pass_,
            message=f"Software inventory contains {len(evidence.software)} components",
        )
    return CheckResult(
        check_id=check.id,
        status=Status.fail,
        message=check.fail_message or "No software inventory",
    )


def _check_kev_match(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if not evidence.software:
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message="No software evidence to correlate with KEV",
        )
    if not evidence.kev_cves:
        return CheckResult(
            check_id=check.id,
            status=Status.unknown,
            message="KEV catalog not loaded",
        )
    hits: list[str] = []
    for comp in evidence.software:
        for cve in comp.cves:
            if cve.upper() in evidence.kev_cves:
                hits.append(f"{comp.name}@{comp.version or '?'}:{cve.upper()}")
    if hits:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or "Known exploited vulnerabilities present") + ": " + ", ".join(hits),
            evidence_refs=hits,
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message="No SBOM CVE identifiers match the KEV catalog",
    )


def _check_pcap_cleartext(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if not evidence.pcap_flows:
        return CheckResult(
            check_id=check.id,
            status=Status.not_applicable,
            message="No passive PCAP supplied (optional evidence)",
        )
    ports = set(check.ports) if check.ports else None
    hits = []
    for flow in evidence.pcap_flows:
        if not flow.cleartext:
            continue
        if ports and flow.dst_port not in ports and flow.src_port not in ports:
            continue
        hits.append(f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}")
    if hits:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or "Cleartext or weakly protected services observed")
            + ": "
            + "; ".join(hits[:20]),
            evidence_refs=hits[:20],
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message=f"No cleartext services in {len(evidence.pcap_flows)} passive flows",
    )


def _check_pcap_cross_zone(check: CheckSpec, evidence: EvidenceBundle) -> CheckResult:
    if not evidence.pcap_flows:
        return CheckResult(
            check_id=check.id,
            status=Status.not_applicable,
            message="No passive PCAP supplied (optional evidence)",
        )
    forbidden = {tuple(pair) for pair in (check.forbid_pairs or [["it", "ot"], ["internet", "ot"]])}
    hits = []
    for flow in evidence.pcap_flows:
        pair = (flow.src_zone or "unknown", flow.dst_zone or "unknown")
        if pair in forbidden:
            hits.append(f"{flow.src_ip}({pair[0]})->{flow.dst_ip}({pair[1]}):{flow.dst_port}")
    if hits:
        return CheckResult(
            check_id=check.id,
            status=Status.fail,
            message=(check.fail_message or "Cross-zone traffic observed") + ": " + "; ".join(hits[:20]),
            evidence_refs=hits[:20],
        )
    return CheckResult(
        check_id=check.id,
        status=Status.pass_,
        message="No forbidden cross-zone pairs in passive flows",
    )


def _matching_assets(rule: RuleSpec, evidence: EvidenceBundle) -> list[Asset]:
    types: list[str] = []
    for check in rule.checks:
        types.extend(check.where.get("type_in") or [])
    if not types:
        return evidence.assets
    return [a for a in evidence.assets if a.type in types]


def _asset_ids_from_message(result: CheckResult) -> list[str]:
    return list(result.evidence_refs)
