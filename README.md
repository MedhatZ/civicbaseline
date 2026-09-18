# CivicBaseline

[![CI](https://github.com/MedhatZ/civicbaseline/actions/workflows/ci.yml/badge.svg)](https://github.com/MedhatZ/civicbaseline/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Evidence engine that turns CISA CPGs into **safe, prioritized actions** for under-resourced U.S. critical-infrastructure operators.

CivicBaseline reads files you already have — asset inventories, firewall exports, account lists, SBOMs, and optional **passive** PCAP captures — and reports baseline gaps. It does **not** scan PLCs, inject industrial protocols, or ship exploits.

> Independent open-source project. Not a CISA, EPA, HHS, or NIST product. Checks use **original language** aligned to public [CISA CPG 2.0](https://www.cisa.gov/cross-sector-cybersecurity-performance-goals) themes. Scores are a gap assistant, not a certification.

## Why it exists

CISA’s Cross-Sector Cybersecurity Performance Goals are a national baseline, not a vendor product. CISA has also said **small organizations struggle to turn those goals into concrete action**. Most U.S. community water systems, many rural hospitals, and many distribution cooperatives cannot buy an OT detection platform.

CivicBaseline is Apache-2.0 public infrastructure for that gap: repeatable evidence checks, sector overlays (water, healthcare, energy), and reports a superintendent or plant operator can act on.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/MedhatZ/civicbaseline.git
cd civicbaseline
python -m pip install -e ".[dev]"
python -m pytest
civicbaseline assess --pack water --evidence fixtures/water-plant --out reports/water
```

Open `reports/water/report.html` or `report.md`. The Cedar Creek fixture is **synthetic and intentionally weak** so the report shows prioritized gaps.

Other packs:

```bash
civicbaseline assess --pack healthcare --evidence fixtures/hospital --out reports/hospital
civicbaseline assess --pack energy --evidence fixtures/substation --out reports/energy
civicbaseline packs
```

Optional: correlate SBOM CVE **identifiers** with the CISA Known Exploited Vulnerabilities catalog (no exploit details):

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
| `zones.yaml` | Optional IP-to-zone map for passive PCAP |
| `sbom.json` | CycloneDX or SPDX JSON |
| `traffic.pcap` | Optional SPAN/mirror capture, read-only |

Schema notes: [`docs/en/evidence-schema.md`](docs/en/evidence-schema.md)

## Packs

| Pack | Contents |
| --- | --- |
| `cpg2` | Original checks mapped to CPG 2.0 / NIST CSF 2.0 functions |
| `water` | `cpg2` + EPA water/wastewater checklist **themes** |
| `healthcare` | `cpg2` + HHS/CISA healthcare SSG **themes** |
| `energy` | `cpg2` + energy distribution/DER SSG **themes** |

## Safety

Read [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) before running against real operator data.

- No default-on discovery of PLCs, RTUs, or IEDs
- No exploit payloads or proof-of-concept attacks
- Passive PCAP only if you already captured it under change control
- Remediation text assumes a maintenance window, a backup, and a vendor procedure

## Documentation

| Doc | What it is |
| --- | --- |
| [`docs/README.md`](docs/README.md) | Index |
| [`docs/ar/01-market-and-national-interest.md`](docs/ar/01-market-and-national-interest.md) | Arabic professional analysis |
| [`docs/en/niw-endeavor-brief.md`](docs/en/niw-endeavor-brief.md) | English endeavor brief (not legal advice) |
| [`docs/en/competitive-landscape.md`](docs/en/competitive-landscape.md) | How this differs from CSET / commercial OT tools |
| [`docs/en/sample-water-report.md`](docs/en/sample-water-report.md) | Sample report from the synthetic water plant |

## Project files

- [LICENSE](LICENSE) — Apache License 2.0
- [SECURITY.md](SECURITY.md) — how to report flaws in *this* tool
- [CONTRIBUTING.md](CONTRIBUTING.md) — defensive contributions only
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [NOTICE](NOTICE) — trademarks and framework alignment

## License

Copyright 2026 CivicBaseline contributors.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
