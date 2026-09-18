#!/usr/bin/env python3
"""Build release notes artifacts: coverage snapshot, CycloneDX stub for this repo, KPI skeleton."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from civicbaseline import __version__
from civicbaseline.packs import list_packs, load_rules_for_pack


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    packs = []
    total_rules = 0
    for pack in list_packs():
        spec, rules = load_rules_for_pack(pack.id)
        packs.append({"id": spec.id, "name": spec.name, "rule_count": len(rules)})
        if pack.id in {"cpg2", "water-epa", "healthcare-ssg", "energy-der"}:
            total_rules += len(rules)

    snapshot = {
        "project": "civicbaseline",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "unique_overlay_rules": total_rules,
        "packs": packs,
        "signing": "Add Sigstore cosign sign-blob on the GitHub Release when publishing v0.1+.",
    }
    (out / "impact-snapshot.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "civicbaseline",
                "version": __version__,
            },
            "properties": [
                {"name": "civicbaseline:note", "value": "Stub SBOM of this tool; replace with cdxgen/syft in production releases."}
            ],
        },
        "components": [
            {"type": "library", "name": "pydantic", "scope": "required"},
            {"type": "library", "name": "pyyaml", "scope": "required"},
            {"type": "library", "name": "jinja2", "scope": "required"},
        ],
    }
    (out / "civicbaseline.cdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    (out / "README.txt").write_text(
        "CivicBaseline release artifacts\n"
        "See docs/en/release-and-signing.md for Sigstore steps.\n",
        encoding="utf-8",
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
