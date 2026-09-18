# Partnerships and outreach

Templates for maintainers. Replace bracketed text. Do not claim CISA affiliation.

## 1. Rural water / small utility (email)

Subject: Free, offline cybersecurity baseline check for small water systems

Hello [Name],

I maintain CivicBaseline, an open-source tool that helps small water and wastewater systems turn CISA-style baseline practices into a short report. It runs on files you already have (asset list, firewall rules, backup notes). It does **not** scan PLCs or require a cloud account.

If useful, we can walk through the public Cedar Creek sample report in 20 minutes, then optionally run the tool on a spreadsheet you export—no process-network scanning.

The project: [repo URL]

Thank you for the work you already do keeping water safe.

## 2. Rural hospital CISO / IT lead

Subject: Open-source CPG/SSG gap check for community hospitals

CivicBaseline maps operator evidence to healthcare sector-specific goal *themes* (inventory of networked devices, EHR restore, BAAs, BMS segmentation). It is a gap assistant, not a HIPAA certification. Happy to share a synthetic 25-bed hospital report and the YAML so your team can audit the rules before any internal data is used.

## 3. Cooperative / distribution utility

Subject: Distribution and DER baseline checks (not a CIP audit)

The energy pack looks at DER gateway remote access, relay change control, ADMS/SCADA segmentation, and IED firmware provenance. It is **not** a NERC CIP audit. Intended for cooperatives and public-power distributors that want a free first pass before hiring an assessor.

## 4. Conference abstract (defensive)

Title: Translating CPG 2.0 into evidence checks small operators can run without scanning a PLC

Abstract: CISA’s Cross-Sector CPGs are the national baseline, yet small water, hospital, and distribution operators still complete them as interviews—if at all. CivicBaseline is an Apache-2.0 engine that evaluates inventories, SBOMs, and optional passive captures against original YAML rules aligned to CPG 2.0 and sector overlays. This talk shows the architecture, the safety constraints (no ICS exploits, no default-on controller scans), and a live report from a synthetic water plant. Attendees leave with a repo they can fork for state technical-assistance programs.

Venues: S4x, Black Hat Arsenal (tool demo, defensive), RSA, AWWA ACE, state rural water associations, ISA analysis-of-OT sessions.

## 5. What not to do

- Do not cold-email CISA staff claiming a partnership that does not exist.
- Do not send live plant PCAPs to public GitHub issues.
- Do not offer to “prove” a finding by exploiting a controller.
