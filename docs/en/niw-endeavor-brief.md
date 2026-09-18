# Proposed Endeavor Brief: CivicBaseline

**Use:** Supporting exhibit for an EB-2 National Interest Waiver petition (Matter of Dhanasar).  
**Status:** Technical and policy brief. **Not legal advice.** A qualified immigration attorney should adapt this language to the petitioner’s credentials and evidence.  
**Project:** CivicBaseline, an open-source evidence engine for critical-infrastructure cybersecurity baselines.  
**Date:** September 2026.

---

## 1. Proposed endeavor (plain statement)

The petitioner’s proposed endeavor is to **design, maintain, and freely disseminate CivicBaseline**, an open-source, defensive cybersecurity assessment engine that translates the U.S. government’s voluntary Cross-Sector Cybersecurity Performance Goals (CISA CPG 2.0) and related sector guidance into **repeatable, evidence-based checks** for under-resourced operators of U.S. critical infrastructure—initially drinking water and wastewater systems, then healthcare facilities and electric distribution / distributed energy resources (DER).

The endeavor is not generic software engineering and not a commercial product for a single employer. It is a public-interest engineering program: publish machine-readable control packs, a safe-by-default assessment CLI, sector overlays (EPA water checklist themes, HHS healthcare sector-specific goals, energy distribution/DER goals), and signed releases so small U.S. operators can measure and close baseline gaps without active scanning of industrial controllers and without purchasing an OT security platform.

---

## 2. Occupation versus endeavor

| | Description |
|---|---|
| Occupation | Cybersecurity engineer / secure-systems engineer focused on operational technology (OT) and critical infrastructure. |
| Endeavor | Build and steward CivicBaseline as national-scale public infrastructure: CPG-aligned evidence checks, sector packs, supply-chain (SBOM/KEV) correlation, and operator-facing remediation guidance. |

This distinction follows USCIS guidance that the endeavor must be more specific than the occupation. Analogous to *Dhanasar* (engineer vs. propulsion R&D), the occupation is cybersecurity engineering; the endeavor is **raising the cybersecurity baseline of small U.S. critical-infrastructure operators through open evidence automation**.

---

## 3. Prong 1 — Substantial merit and national importance

### Substantial merit

The work has substantial merit in cybersecurity, public health, and economic resilience. Water treatment, hospital operations, and electric distribution are safety-critical processes. Misconfigurations, default credentials, absent inventories, untested backups, and unknown software components are well-documented precursors to ransomware and process disruption. A tool that detects those gaps from operator-owned evidence, and that refuses unsafe active exploitation of PLCs, has intrinsic technical and civic merit.

### National importance

National importance does not require a federal contract. It requires implications beyond one employer or locality. CivicBaseline is nationally important because:

1. **Federal policy already names the problem.** National Security Memorandum on Critical Infrastructure Security and Resilience (NSM-22) reaffirms 16 sectors whose disruption would harm security, the economy, or public health. The National Cybersecurity Strategy and Implementation Plan call for baseline practices across critical infrastructure, with explicit attention to water and healthcare. CISA’s CPG 2.0 is written as a **national aggregate-risk** baseline, not a private maturity model.

2. **CISA documented an adoption gap the endeavor targets.** CPG 2.0 states that smaller organizations struggle to turn high-level goals into concrete action, and that this gap has shown up in ransomware against schools and hospitals and in campaigns against government and critical infrastructure. CivicBaseline’s design—executable checks, cost/impact/ease prioritization, non-expert reports—is a direct response to that federal finding.

3. **The beneficiaries are geographically and sectorally dispersed.** There are tens of thousands of U.S. community water systems, many of them small; rural hospitals; and distribution utilities that fall outside the best-resourced NERC CIP environments. An Apache-2.0 tool used by any of them has national reach even if each deployment is local.

4. **Open source is the delivery mechanism for national benefit.** Commercial OT platforms are not reachable for most small utilities. A closed consulting practice would capture value for one firm. A public rule pack can be audited, forked by state fusion centers or university extension programs, and used in EPA/CISA technical-assistance workflows without procurement.

**Authorities and frameworks the endeavor aligns to (non-exhaustive):** NSM-22; National Cybersecurity Strategy / Implementation Plan; CISA Cross-Sector CPG 2.0 and Sector-Specific Goals; NIST CSF 2.0; NIST SP 800-82r3; EPA cybersecurity guidance for drinking water and wastewater; HHS healthcare cybersecurity performance goals; EO 14028 software-supply-chain / SBOM policy; CISA Known Exploited Vulnerabilities catalog.

CivicBaseline does not claim to be a CISA, EPA, or HHS product and does not issue regulatory certifications.

---

## 4. Prong 2 — Well positioned to advance the endeavor

This section is a **template**. Counsel should attach the petitioner’s actual record.

Evidence that typically positions a petitioner to advance *this* endeavor:

- Advanced degree or progressive experience in cybersecurity, industrial control, or critical-infrastructure protection.
- Demonstrable defensive engineering: inventories, hardening, detection engineering, secure SDLC—not offensive exploit development.
- Public artifacts from this repository: dated releases, test coverage, signed binaries, SBOM of the tool itself.
- Technical writing (the Arabic market analysis and this brief; a later short paper on translating CPG 2.0 into evidence checks for small water systems).
- Outreach: conference submissions (S4x, Black Hat Arsenal *defensive* track, RSA), rural water or hospital associations, ISA99 / IEC 62443 community.
- Independent letters: utility operators, hospital CISOs, academic OT labs, or former CISA assessors describing use or review—not co-authors of the petition.

The repository is structured so that **progress is measurable**: pack coverage versus CPG themes, fixture-based regression tests, SARIF/JSON outputs, and an impact log (`docs/en/impact-kpis.md`).

---

## 5. Prong 3 — On balance, a waiver is beneficial

Waiving the job offer and labor certification is beneficial because:

1. **The endeavor is multi-stakeholder by nature.** Maintaining public control packs for water, healthcare, and energy operators, state grant programs, and educators is poorly matched to a single-employer PERM role. The national benefit is diluted if the work is captive to one company’s customers.

2. **Even if U.S. workers are available for “cybersecurity engineer” jobs, the United States still benefits** from this specific public-good artifact. *Dhanasar* does not require a labor shortage; it asks whether, on balance, the nation benefits from the waiver. A free baseline engine for small utilities is such a benefit.

3. **Urgency and impracticality of PERM.** Critical-infrastructure incidents do not wait for a multi-year certification for one employer. Open-source maintainership, community rule reviews, and unpaid operator pilots are activities PERM is not designed to capture.

4. **No adverse effect on U.S. labor.** The tool reduces cost for U.S. operators and can be extended by U.S. contributors. It does not displace assessors; it complements CSET interview assessments with evidence automation.

---

## 6. What this endeavor is not

- Not a vulnerability exploit framework, ICS attack simulator, or default-on port scanner against PLCs.
- Not a request that USCIS endorse a commercial startup, though a future services layer around training would remain secondary to the public engine.
- Not a claim of unique genius; the claim is a **specific, nationally important program of work** the petitioner is positioned to carry out.

---

## 7. Near-term work plan (endeavor execution)

| Window | Deliverable | National-interest nexus |
|---|---|---|
| Months 0–2 | CPG-aligned engine + EPA water overlay + public water-plant fixture | Small water systems, EPA checklist themes |
| Months 2–4 | CycloneDX/SPDX ingest + CISA KEV correlation; healthcare SSG pack | Software transparency (EO 14028) + hospitals |
| Months 4–6 | Energy distribution/DER pack; optional passive PCAP checks | Grid-edge / DER expansion |
| Ongoing | Signed releases, SLSA-oriented publishing, operator pilots, defensive talks | Trust, adoption, replicability |

Detailed KPIs and outreach templates: [`impact-kpis.md`](impact-kpis.md), [`partnerships-and-outreach.md`](partnerships-and-outreach.md), [`release-and-signing.md`](release-and-signing.md).

---

## 8. Suggested exhibit list (for counsel)

1. This brief.  
2. Arabic professional analysis (`docs/ar/01-market-and-national-interest.md`).  
3. Competitive landscape (`docs/en/competitive-landscape.md`).  
4. Repository license, acceptable-use policy, and security policy.  
5. Release history, test results, and sample reports from `fixtures/`.  
6. Petitioner CV, degrees, and expert letters.  
7. Any third-party adoption (issues, forks, thank-you letters from operators).

---

*CivicBaseline is an independent open-source project. References to CISA, EPA, HHS, NIST, and NERC describe public policy alignment only.*
