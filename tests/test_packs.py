from __future__ import annotations

from pathlib import Path

from civicbaseline.engine import assess
from civicbaseline.evidence import load_evidence
from civicbaseline.kev import load_kev_cves
from civicbaseline.models import Status
from civicbaseline.packs import load_rules_for_pack
from civicbaseline.scoring import summarize

ROOT = Path(__file__).resolve().parent.parent


def _run(pack: str, fixture: str):
    spec, rules = load_rules_for_pack(pack)
    kev = load_kev_cves()
    evidence = load_evidence(ROOT / "fixtures" / fixture, kev_cves=kev)
    results = assess(rules, evidence)
    summary = summarize(spec.id, spec.name, evidence.organization, evidence.sector, results)
    by_id = {item.rule.id: item for item in results}
    return summary, by_id, evidence


def test_water_fixture_fails_signature_controls():
    summary, by_id, evidence = _run("water", "water-plant")
    assert evidence.sbom_present
    assert summary.failed >= 8
    assert summary.score < 40
    assert by_id["CPG2-PR-01"].status == Status.fail
    assert by_id["CPG2-PR-03"].status == Status.fail
    assert by_id["WATER-02"].status == Status.fail
    assert by_id["CPG2-RC-02"].status == Status.fail
    assert any("CVE-2021-44228" in c.message for c in by_id["CPG2-RC-02"].checks)


def test_water_pcap_flags_telnet_and_cross_zone():
    _, by_id, evidence = _run("water", "water-plant")
    assert evidence.pcap_flows
    assert by_id["CPG2-DE-02"].status == Status.fail
    assert by_id["CPG2-DE-03"].status == Status.fail


def test_hardened_fixture_scores_higher_than_broken_plant():
    broken, _, _ = _run("water", "water-plant")
    hard, by_id, _ = _run("water", "water-plant-hardened")
    assert hard.score > broken.score
    assert by_id["CPG2-PR-01"].status == Status.pass_
    assert by_id["CPG2-PR-03"].status == Status.pass_
    assert by_id["CPG2-RC-01"].status == Status.pass_
    assert by_id["WATER-05"].status == Status.pass_


def test_healthcare_overlay_and_kev():
    summary, by_id, _ = _run("healthcare", "hospital")
    assert summary.failed >= 5
    assert by_id["HEALTH-01"].status == Status.fail
    assert by_id["HEALTH-02"].status == Status.fail
    assert by_id["HEALTH-04"].status == Status.fail
    assert by_id["CPG2-RC-02"].status == Status.fail


def test_energy_overlay_and_spdx_sbom():
    _, by_id, evidence = _run("energy", "substation")
    assert evidence.sbom_present
    assert any(c.name == "adms-core" for c in evidence.software)
    assert by_id["ENERGY-01"].status == Status.fail
    assert by_id["ENERGY-03"].status == Status.fail
    assert by_id["ENERGY-05"].status == Status.fail
    assert by_id["CPG2-DE-02"].status == Status.fail
