from __future__ import annotations

import argparse
import sys
from pathlib import Path

from civicbaseline import __version__
from civicbaseline.engine import assess
from civicbaseline.evidence import load_evidence
from civicbaseline.kev import load_kev_cves
from civicbaseline.packs import list_packs, load_rules_for_pack
from civicbaseline.report import write_reports
from civicbaseline.scoring import summarize


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="civicbaseline",
        description=(
            "Defensive evidence engine for CISA CPG-style baselines. "
            "Reads operator-owned files. Does not scan or exploit controllers."
        ),
    )
    parser.add_argument("--version", action="version", version=f"civicbaseline {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    assess_p = sub.add_parser("assess", help="Run a pack against an evidence directory")
    assess_p.add_argument("--pack", "-p", required=True, help="Pack id: water, healthcare, energy, cpg2")
    assess_p.add_argument("--evidence", "-e", required=True, help="Directory of YAML/JSON/PCAP evidence")
    assess_p.add_argument("--out", "-o", default="reports/latest", help="Output directory")
    assess_p.add_argument(
        "--format",
        default="md,html,json,sarif",
        help="Comma-separated: md,html,json,sarif",
    )
    assess_p.add_argument("--kev", help="Path to a local CISA KEV JSON file")
    assess_p.add_argument(
        "--fetch-kev",
        action="store_true",
        help="Download the CISA KEV catalog (identifiers only)",
    )
    assess_p.add_argument("--packs-root", help="Override packs directory")

    packs_p = sub.add_parser("packs", help="List available rule packs")
    packs_p.add_argument("--packs-root", help="Override packs directory")

    args = parser.parse_args(argv)
    if args.command == "packs":
        root = Path(args.packs_root) if args.packs_root else None
        for pack in list_packs(root):
            included = f" (includes: {', '.join(pack.includes)})" if pack.includes else ""
            print(f"{pack.id:12} {pack.name}{included}")
        return 0

    packs_root = Path(args.packs_root) if args.packs_root else None
    spec, rules = load_rules_for_pack(args.pack, packs_root)
    kev = load_kev_cves(path=args.kev, fetch=args.fetch_kev)
    evidence = load_evidence(args.evidence, kev_cves=kev)
    rule_results = assess(rules, evidence)
    summary = summarize(spec.id, spec.name, evidence.organization, evidence.sector, rule_results)
    formats = [part.strip() for part in args.format.split(",") if part.strip()]
    written = write_reports(summary, args.out, formats)
    print(f"{summary.organization}  pack={summary.pack_id}  score={summary.score}")
    print(f"pass={summary.passed}  fail={summary.failed}  unknown={summary.unknown}  n/a={summary.not_applicable}")
    print("wrote:")
    for path in written:
        print(f"  {path}")
    return 0 if summary.failed == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
