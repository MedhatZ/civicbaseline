# Competitive landscape

CivicBaseline is positioned as a **safe, evidence-based CPG translator for small U.S. operators**, not as a general vulnerability scanner and not as a CISA replacement. This note records how neighboring tools relate so the project does not duplicate them and so NIW materials can explain novelty without overclaiming.

## Government and interview-centric assessment

| Tool | Owner | Role | Gap CivicBaseline fills |
|---|---|---|---|
| CSET | CISA / INL | Interview- and questionnaire-driven evaluation against many standards; CPG assessment training is built around CSET | CSET is the right tool for facilitated assessments. It is not a CI-friendly evidence engine. CivicBaseline ingests operator files and re-runs checks between CSET cycles. Complement, not fork. |
| CISA CPG 2.0 Checklist / CSET CPG 2.0 module | CISA | Authoritative goal text and (when shipped) official checklist module | CivicBaseline uses **original check language** aligned to public CPG *themes*. It does not copy CPG prose or CISA marks. |

## Commercial OT platforms

Dragos, Claroty, Nozomi, and similar platforms provide deep protocol visibility, threat detection, and asset discovery for organizations that can buy and staff them. They are the right answer for large generation plants and well-funded hospital systems. They are the wrong answer for a five-person water utility. CivicBaseline’s adoption thesis is **price zero + evidence the operator already has**, not competing on ICS protocol depth.

## Open-source OT labs and validation

| Project | Role | Why we do not overlap |
|---|---|---|
| GRFICS | Containerized chemical-plant lab for training | Pedagogy and process simulation, not production baseline assessment. |
| ICSForge | Generates OT traffic to validate detections (ATT&CK for ICS) | Coverage testing for SOCs. CivicBaseline never injects industrial traffic. |
| NSA GRASSMARLIN / MarlinSpike | Passive topology from PCAP | Adjacent. CivicBaseline may *optionally read* a PCAP the user supplies for cleartext and zone-crossing hints, then maps those hints to CPG-style goals. It is not a topology product. |

## Unsafe or IT-centric scanners

Nuclei, OpenVAS, and live Nmap against PLCs can disrupt physical processes. kube-bench, Trivy, and Checkov are excellent for cloud and Kubernetes and irrelevant to most pump stations. CivicBaseline’s default path is **files in, findings out**. Active controller scanning is out of scope.

## Academic or nascent hardening CLIs

Small projects appear periodically (zone/conduit checkers, vendor-specific hardeners). They typically lack: CPG 2.0 / SSG pack structure, EPA/HHS overlays, SBOM–KEV correlation, SARIF for grant/workflow use, OT-aware scoring (safety/availability over confidentiality), and an explicit national-interest operator persona. CivicBaseline’s novelty is the **composition** of those pieces under a defensive license and AUP.

## Positioning sentence (for README and talks)

> CivicBaseline does not replace CSET, Dragos, or NIST. It gives a small U.S. water, hospital, or distribution operator a free, repeatable way to turn CISA-style baseline goals into evidence checks they can run without scanning a PLC.
