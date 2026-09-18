from __future__ import annotations

import json
from pathlib import Path

from civicbaseline.cli import main
from civicbaseline.engine import assess
from civicbaseline.evidence import load_evidence
from civicbaseline.kev import load_kev_cves
from civicbaseline.packs import list_packs, load_rules_for_pack
from civicbaseline.report import render_markdown, write_reports
from civicbaseline.sarif import render_sarif
from civicbaseline.scoring import summarize

ROOT = Path(__file__).resolve().parent.parent


def test_list_packs_includes_sector_bundles():
    ids = {p.id for p in list_packs()}
    assert {"cpg2", "water", "healthcare", "energy", "water-epa", "healthcare-ssg", "energy-der"} <= ids


def test_reports_and_sarif(tmp_path: Path):
    spec, rules = load_rules_for_pack("water")
    evidence = load_evidence(ROOT / "fixtures" / "water-plant", kev_cves=load_kev_cves())
    summary = summarize(spec.id, spec.name, evidence.organization, evidence.sector, assess(rules, evidence))
    md = render_markdown(summary)
    assert "Cedar Creek" in md
    assert "Framework crosswalk" in md
    sarif = json.loads(render_sarif(summary))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    written = write_reports(summary, tmp_path, ["md", "html", "json", "sarif"])
    names = {p.name for p in written}
    assert names == {"report.md", "report.html", "report.json", "report.sarif"}


def test_cli_water(tmp_path: Path):
    code = main(
        [
            "assess",
            "--pack",
            "water",
            "--evidence",
            str(ROOT / "fixtures" / "water-plant"),
            "--out",
            str(tmp_path),
            "--format",
            "md,json",
        ]
    )
    assert code == 2
    assert (tmp_path / "report.md").exists()


def test_cli_packs(capsys):
    assert main(["packs"]) == 0
    out = capsys.readouterr().out
    assert "water" in out
    assert "healthcare" in out
