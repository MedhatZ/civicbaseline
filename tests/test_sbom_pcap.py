from __future__ import annotations

from civicbaseline.pcap import CLEARTEXT_PORTS, ethernet_ip_tcp, load_pcap_flows, write_minimal_pcap
from civicbaseline.sbom import load_software_from_sbom


def test_pcap_roundtrip(tmp_path):
    path = tmp_path / "lab.pcap"
    write_minimal_pcap(path, [ethernet_ip_tcp("192.168.1.10", "192.168.1.20", 4000, 23)])
    flows = load_pcap_flows(path, {"192.168.1.10": "it", "192.168.1.20": "ot"})
    assert len(flows) == 1
    assert flows[0].cleartext
    assert flows[0].dst_port == 23
    assert flows[0].src_zone == "it"
    assert 23 in CLEARTEXT_PORTS


def test_cyclonedx_and_spdx(tmp_path):
    cdx = tmp_path / "bom.json"
    cdx.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "components": [{"name": "demo", "version": "1", "bom-ref": "demo"}],
          "vulnerabilities": [{"id": "CVE-2021-44228", "affects": [{"ref": "demo"}]}]
        }
        """,
        encoding="utf-8",
    )
    comps = load_software_from_sbom(cdx)
    assert comps[0].cves == ["CVE-2021-44228"]

    spdx = tmp_path / "spdx.json"
    spdx.write_text(
        """
        {
          "spdxVersion": "SPDX-2.3",
          "packages": [{"name": "ied-fw", "versionInfo": "4.0"}]
        }
        """,
        encoding="utf-8",
    )
    pkgs = load_software_from_sbom(spdx)
    assert pkgs[0].name == "ied-fw"
    assert pkgs[0].version == "4.0"
