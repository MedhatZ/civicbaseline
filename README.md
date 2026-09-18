<<<<<<< HEAD
# CivicBaseline

Open-source **evidence engine** that turns U.S. critical-infrastructure baseline goals into **safe, repeatable checks** for small operators.

CivicBaseline reads inventories, firewall exports, account lists, SBOMs, and optional **passive** PCAP files you already have. It does **not** scan PLCs, inject industrial protocols, or ship exploits.

> Independent project. Not a CISA, EPA, HHS, or NIST product. Alignment with [CISA CPG 2.0](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals) and sector guidance uses **original check language**. Scores are a gap assistant, not a certification.

## Why it exists

CISA’s Cross-Sector Cybersecurity Performance Goals are written for the nation, not for one vendor. CISA has also said **small organizations struggle to turn those goals into action**. Most U.S. community water systems, many rural hospitals, and many distribution cooperatives cannot buy an OT detection platform. CivicBaseline is Apache-2.0 public infrastructure for that gap.

Professional analysis (Arabic): [`docs/ar/01-market-and-national-interest.md`](docs/ar/01-market-and-national-interest.md)  
EB-2 NIW endeavor brief (English, not legal advice): [`docs/en/niw-endeavor-brief.md`](docs/en/niw-endeavor-brief.md)  
Landscape: [`docs/en/competitive-landscape.md`](docs/en/competitive-landscape.md)  
Sample report (synthetic water plant): [`docs/en/sample-water-report.md`](docs/en/sample-water-report.md)

## Quick start

```bash
python -m pip install -e ".[dev]"
python -m pytest
civicbaseline packs
civicbaseline assess --pack water --evidence fixtures/water-plant --out reports/water
```

Open `reports/water/report.md` (or `report.html`). The Cedar Creek fixture is **synthetic and intentionally weak** so the report shows prioritized gaps.

Other packs:

```bash
civicbaseline assess --pack healthcare --evidence fixtures/hospital --out reports/hospital
civicbaseline assess --pack energy --evidence fixtures/substation --out reports/energy
```

Optional: correlate SBOM CVE identifiers with the CISA KEV catalog (IDs only):

```bash
civicbaseline assess --pack water --evidence fixtures/water-plant --fetch-kev
# or a vendored JSON:
civicbaseline assess --pack water --evidence fixtures/water-plant --kev data/kev-sample.json
```

## What you feed it

Place YAML/JSON in an evidence directory (see `fixtures/water-plant/`):

| File | Purpose |
| --- | --- |
| `inventory.yaml` | Assets, zones, firmware, MFA, default-password flags |
| `firewall.yaml` | Zone-to-zone allow/deny (no live probing) |
| `accounts.yaml` | Shared/default/MFA account evidence |
| `policies.yaml` | Backups, IR, governance, sector overlays |
| `zones.yaml` | Optional IP → zone map for passive PCAP |
| `sbom.json` | CycloneDX or SPDX JSON |
| `traffic.pcap` | Optional SPAN/mirror capture, read-only |

## Packs

| Pack | Contents |
| --- | --- |
| `cpg2` | Original checks mapped to CPG 2.0 / NIST CSF 2.0 functions |
| `water` | `cpg2` + EPA water/wastewater checklist **themes** |
| `healthcare` | `cpg2` + HHS/CISA healthcare SSG **themes** |
| `energy` | `cpg2` + energy distribution/DER SSG **themes** |

## Safety

Read [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md). Default-on active discovery of controllers is out of scope on purpose. Remediation text always assumes a maintenance window, a backup, and a vendor procedure.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
=======
# civicbaseline
Evidence engine that turns CISA CPGs into safe, prioritized actions for under-resourced critical infrastructure operators
>>>>>>> 7df929b6ff2b9fb8b9793409947fcefee4ef1291
