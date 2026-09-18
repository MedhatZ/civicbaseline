from __future__ import annotations

import json

from civicbaseline.models import AssessmentResult, Status

_LEVEL = {
    Status.fail: "error",
    Status.unknown: "note",
    Status.pass_: "none",
    Status.not_applicable: "none",
}

_SEC_SEV = {
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
}


def render_sarif(result: AssessmentResult) -> str:
    rules = []
    results = []
    for item in result.rules:
        rule = item.rule
        rules.append(
            {
                "id": rule.id,
                "name": rule.id,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.summary or rule.title},
                "helpUri": "https://www.cisa.gov/cross-sector-cybersecurity-performance-goals",
                "properties": {
                    "nist_csf": rule.nist_csf,
                    "mitre_ics": rule.mitre_ics,
                    "cost": rule.cost.value,
                    "impact": rule.impact.value,
                    "ease": rule.ease.value,
                    "function": rule.function,
                },
                "defaultConfiguration": {"level": "error" if rule.impact.value == "high" else "warning"},
            }
        )
        if item.status not in {Status.fail, Status.unknown}:
            continue
        message = "; ".join(c.message for c in item.checks if c.status in {Status.fail, Status.unknown})
        results.append(
            {
                "ruleId": rule.id,
                "level": _LEVEL[item.status],
                "message": {"text": message or item.status.value},
                "properties": {
                    "priority": item.priority,
                    "status": item.status.value,
                    "overlays": rule.overlays,
                    "security-severity": _SEC_SEV.get(rule.impact.value, "5.0"),
                },
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CivicBaseline",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/civicbaseline/civicbaseline",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "organization": result.organization,
                    "pack": result.pack_id,
                    "score": result.score,
                    "disclaimer": "Gap assistant only; not a regulatory certification.",
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)
