# Sample report — Cedar Creek Water Works (synthetic)

Checked-in snapshot from `civicbaseline assess --pack water --evidence fixtures/water-plant`. The plant is fictional and intentionally misconfigured. Not a real utility.

---

# CivicBaseline assessment

**Operator:** Cedar Creek Water Works (synthetic)  
**Sector:** water  
**Pack:** Small water and wastewater baseline (CPG 2.0 themes + EPA checklist themes) (`water`)  
**Generated:** 2026-09-18 07:07 UTC  
**Baseline score:** **12.1** / 100 (OT-weighted)

| Pass | Fail | Unknown | N/A |
| ---: | ---: | ---: | ---: |
| 3 | 21 | 0 | 0 |

> CivicBaseline is a **gap assistant**, not a CISA product and not a NERC CIP, HIPAA, or IEC 62443 certification. Do not scan live PLCs to create evidence.

## What leadership needs to know

The highest-priority gaps (impact × ease × OT criticality):

1. **Segment IT, OT, and internet; deny any-any conduits** (`CPG2-PR-03`) — impact high, ease medium, priority 8.8
1. **Back up PLC logic that drives chemical feed and pumps** (`WATER-03`) — impact high, ease medium, priority 8.8
1. **Separate business PCs from the process network** (`WATER-04`) — impact high, ease medium, priority 8.8
1. **Back up OT logic and configurations offline** (`CPG2-PR-04`) — impact high, ease medium, priority 7.48
1. **Protect vendor remote support into the plant** (`WATER-06`) — impact high, ease medium, priority 7.48
1. **Require phishing-resistant MFA on remote access** (`CPG2-PR-02`) — impact high, ease medium, priority 7.04
1. **Test restores of OT backups** (`CPG2-RC-01`) — impact high, ease medium, priority 7.04
1. **Review passive captures for IT-to-OT conversations (optional)** (`CPG2-DE-03`) — impact high, ease medium, priority 6.6

## Engineer hardening checklist

Work in a maintenance window. Back up logic and configurations first. Coordinate with the process engineer.

### CPG2-PR-03 — Segment IT, OT, and internet; deny any-any conduits

- NIST CSF 2.0: PR.IR-01, PR.AA-05
- ATT&CK for ICS (mapping only): T0887, T0842
- Cost / impact / ease: medium / high / medium

- Finding: Enabled allow rules create an IT/OT or internet/OT conduit: allow-office-to-ot it->ot/any; allow-internet-mgmt internet->ot/https

Safe next steps:

- Place a firewall or layer-3 ACL between business LAN and process LAN.
- Allow only historian and jump-host conduits; deny internet to OT.
- Test failover of the process network in a maintenance window with operations present.

### WATER-03 — Back up PLC logic that drives chemical feed and pumps

- NIST CSF 2.0: PR.DS-11
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / medium

- Finding: PLC/HMI logic for treatment is not in the backup set

Safe next steps:

- Export projects from the engineering workstation after every integrator change.
- Keep a paper copy of setpoints (chlorine residual, high-service pressure) for manual operation.

### WATER-04 — Separate business PCs from the process network

- NIST CSF 2.0: PR.IR-01
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: medium / high / medium

- Finding: Water plant firewall still allows IT or internet into OT: allow-office-to-ot it->ot/any; allow-internet-mgmt internet->ot/https

Safe next steps:

- Use a dedicated operator workstation on the OT LAN; block the front-office VLAN.

### CPG2-PR-04 — Back up OT logic and configurations offline

- NIST CSF 2.0: PR.DS-11
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: medium / high / medium

- Finding: OT backups are not configured
- Finding: Backups do not include HMI applications and PLC logic

Safe next steps:

- Export PLC projects and HMI applications to encrypted offline media after every change.
- Store a copy off-site or immutable; do not keep the only copy on the engineering laptop.

### WATER-06 — Protect vendor remote support into the plant

- NIST CSF 2.0: PR.AA-03
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / medium

- Finding: Remote access into the water plant lacks MFA: jump-1, vpn-1

Safe next steps:

- Switch vendor access to an attended jump host with MFA; disable always-on modems.

### CPG2-PR-02 — Require phishing-resistant MFA on remote access

- NIST CSF 2.0: PR.AA-03, PR.AA-04
- ATT&CK for ICS (mapping only): T0886
- Cost / impact / ease: medium / high / medium

- Finding: Remote-access assets lack MFA: jump-1, vpn-1

Safe next steps:

- Enable MFA on the VPN or identity provider that fronts the jump host.
- Do not place MFA prompts on the PLC itself; protect the path to OT.
- Phishing-resistant methods (FIDO2) are preferred when the IdP allows them.

### CPG2-RC-01 — Test restores of OT backups

- NIST CSF 2.0: RC.RP-01, PR.DS-11
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: medium / high / medium

- Finding: OT backups have not been restore-tested
- Finding: Backups are not offline or immutable

Safe next steps:

- Restore an HMI project onto a spare workstation in the shop, not onto the live process.
- Record the time to restore; aim for a documented RTO operations will accept.
- Prefer offline or immutable copies so ransomware cannot encrypt the backup.

### CPG2-DE-03 — Review passive captures for IT-to-OT conversations (optional)

- NIST CSF 2.0: DE.CM-06, PR.IR-01
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / medium

- Finding: Passive capture shows IT or internet talking directly to OT: 192.168.20.5(it)->192.168.10.10(ot):23; 192.168.20.5(it)->192.168.10.10(ot):80; 203.0.113.9(internet)->192.168.10.10(ot):502

Safe next steps:

- Confirm whether the flow is a sanctioned historian path; if not, add a firewall deny.
- Update the zone map when addresses change.

### CPG2-ID-02 — Record firmware and patch state for controllers and HMIs

- NIST CSF 2.0: ID.AM-02, ID.RA-01
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / medium

- Finding: Controllers or hosts are missing firmware versions: vpn-1 (missing firmware)

Safe next steps:

- Copy firmware strings from the vendor HMI/engineering workstation, not from a live scan of the PLC.
- Track patch_status as current, lagging, or unknown until the vendor confirms.

### CPG2-PR-05 — Encrypt remote administration paths

- NIST CSF 2.0: PR.DS-02, PR.IR-01
- ATT&CK for ICS (mapping only): T0886
- Cost / impact / ease: medium / high / medium

- Finding: Remote-access assets are not marked as encrypted: jump-1

Safe next steps:

- Replace Telnet/FTP/HTTP admin with vendor-supported TLS or a jump host over VPN.
- Never enable encryption by scanning the PLC; use the vendor engineering procedure.

### CPG2-RC-02 — Prioritize known-exploited software on the inventory

- NIST CSF 2.0: ID.RA-01, RS.AN-03
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / medium

- Finding: SBOM CVE identifiers match the CISA Known Exploited Vulnerabilities catalog: log4j-core@2.14.1:CVE-2021-44228

Safe next steps:

- If a KEV identifier appears, call the OEM for a supported patch or compensating segmentation.
- Apply patches in a maintenance window; never prove exploitability on a live controller.

### CPG2-GV-02 — Hold managed service providers to written security clauses

- NIST CSF 2.0: GV.SC-04, GV.SC-07
- ATT&CK for ICS (mapping only): T0866
- Cost / impact / ease: medium / high / medium

- Finding: MSP or integrator contract lacks security clauses
- Finding: Vendor remote access is not logged

Safe next steps:

- Add remote-access logging and after-hours notification to the integrator contract.
- Disable persistent vendor VPN accounts; issue time-bound access per work order.
- Review who can change PLC logic; require dual control for safety-critical writes.

### WATER-02 — Eliminate default passwords on SCADA, radios, and PLCs

- NIST CSF 2.0: PR.AA-01
- ATT&CK for ICS (mapping only): T0891
- Cost / impact / ease: low / high / high

- Finding: OT-zone water assets still use default credentials: plc-raw, plc-chem

Safe next steps:

- Change OEM defaults on radios and RTUs during a planned pump-off window.
- Coordinate with the integrator so service accounts do not lock the HMI at shift change.

### CPG2-PR-01 — Remove default and shared passwords from OT and remote paths

- NIST CSF 2.0: PR.AA-01, PR.AA-05
- ATT&CK for ICS (mapping only): T0891, T0812
- Cost / impact / ease: low / high / high

- Finding: Assets still use default or well-known credentials: plc-raw, plc-chem, vpn-1
- Finding: Accounts still use default passwords: admin

Safe next steps:

- Change default passwords on PLCs, HMIs, VPNs, and radios during a planned outage.
- Store unique credentials in an offline password manager; do not tape them to the HMI.
- Confirm with the OEM that the change will not fail a watchdog or service account.

### CPG2-DE-02 — Review passive captures for cleartext administration (optional)

- NIST CSF 2.0: DE.CM-01
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / medium / medium

- Finding: Passive capture shows cleartext remote-admin ports: 192.168.20.5:49152->192.168.10.10:23; 192.168.20.5:49153->192.168.10.10:80

Safe next steps:

- Capture only from a mirror port during a change window agreed with operations.
- Replace cleartext admin paths using vendor procedures; do not "test" with active scanners.

### CPG2-DE-01 — Enable logging on jump hosts, firewalls, and HMIs

- NIST CSF 2.0: DE.CM-01, DE.CM-03
- ATT&CK for ICS (mapping only): T0871
- Cost / impact / ease: medium / medium / medium

- Finding: Jump hosts, firewalls, or HMIs do not have logging enabled: hmi-1, jump-1, fw-1

Safe next steps:

- Turn on logging on the firewall and Windows jump host first; PLCs often cannot log densely.
- Forward logs to a cheap syslog or the county SOC if one exists; keep local rotation if not.

### CPG2-GV-01 — Assign a named cybersecurity owner with leadership visibility

- NIST CSF 2.0: GV.RR-01, GV.RR-02
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / high

- Finding: No named cybersecurity owner is evidenced
- Finding: Leadership has not been briefed on cyber risk

Safe next steps:

- Name a primary and backup cyber owner in writing (superintendent plus IT/OT lead is enough for a small utility).
- Add a quarterly one-page brief to the existing board or city-council packet.
- Do not create a new bureaucracy; reuse existing safety-meeting cadence.

### CPG2-RS-01 — Keep a current incident response plan and contacts

- NIST CSF 2.0: RS.MA-01, RS.CO-02
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / high

- Finding: No incident response plan is evidenced
- Finding: Incident contacts are missing or stale

Safe next steps:

- Write a two-page plan covering who isolates the VPN, who calls the county emergency manager, and who talks to the state primacy agency.
- Put after-hours numbers on the control-room wall and in the superintendent's phone.

### WATER-05 — Know whom to call at the primacy agency and CISA

- NIST CSF 2.0: RS.CO-02
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / high / high

- Finding: No evidenced path to notify water regulators during a cyber incident

Safe next steps:

- Add the state water primacy 24/7 number and CISA Central to the incident contact card.

### CPG2-GV-03 — Review privileged access at least annually

- NIST CSF 2.0: GV.OC-05, PR.AA-05
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / medium / high

- Finding: No least-privilege or account review is evidenced
- Finding: Shared or unnamed accounts remain active: admin, vendor

Safe next steps:

- Export account lists from AD, SCADA, and VPN; mark shared and unused accounts.
- Disable unused accounts in a change window; replace shared logins with named accounts where the vendor allows it.

### CPG2-RS-02 — Practice the plan and include ransomware

- NIST CSF 2.0: RS.MA-01, GV.PO-02
- ATT&CK for ICS (mapping only): —
- Cost / impact / ease: low / medium / high

- Finding: No tabletop in the last year
- Finding: No ransomware playbook

Safe next steps:

- Run a 60-minute tabletop once a year with operations, IT, and the mayor or board chair.
- Include a ransomware scenario that encrypts the HMI, not only the business email.


## Framework crosswalk

| ID | Title | Function | Status | NIST CSF 2.0 | Overlays |
| --- | --- | --- | --- | --- | --- |
| CPG2-PR-03 | Segment IT, OT, and internet; deny any-any conduits | PROTECT | fail | PR.IR-01, PR.AA-05 | CPG 2.0 PROTECT |
| WATER-03 | Back up PLC logic that drives chemical feed and pumps | PROTECT | fail | PR.DS-11 | EPA water checklist theme |
| WATER-04 | Separate business PCs from the process network | PROTECT | fail | PR.IR-01 | EPA water checklist theme |
| CPG2-PR-04 | Back up OT logic and configurations offline | PROTECT | fail | PR.DS-11 | CPG 2.0 PROTECT |
| WATER-06 | Protect vendor remote support into the plant | PROTECT | fail | PR.AA-03 | EPA water checklist theme |
| CPG2-PR-02 | Require phishing-resistant MFA on remote access | PROTECT | fail | PR.AA-03, PR.AA-04 | CPG 2.0 PROTECT |
| CPG2-RC-01 | Test restores of OT backups | RECOVER | fail | RC.RP-01, PR.DS-11 | CPG 2.0 RECOVER |
| CPG2-DE-03 | Review passive captures for IT-to-OT conversations (optional) | DETECT | fail | DE.CM-06, PR.IR-01 | CPG 2.0 DETECT, passive PCAP |
| CPG2-ID-02 | Record firmware and patch state for controllers and HMIs | IDENTIFY | fail | ID.AM-02, ID.RA-01 | CPG 2.0 IDENTIFY |
| CPG2-PR-05 | Encrypt remote administration paths | PROTECT | fail | PR.DS-02, PR.IR-01 | CPG 2.0 PROTECT |
| CPG2-RC-02 | Prioritize known-exploited software on the inventory | RECOVER | fail | ID.RA-01, RS.AN-03 | CPG 2.0, CISA KEV |
| CPG2-GV-02 | Hold managed service providers to written security clauses | GOVERN | fail | GV.SC-04, GV.SC-07 | CPG 2.0 GOVERN, MSP risk |
| WATER-02 | Eliminate default passwords on SCADA, radios, and PLCs | PROTECT | fail | PR.AA-01 | EPA water checklist theme |
| CPG2-PR-01 | Remove default and shared passwords from OT and remote paths | PROTECT | fail | PR.AA-01, PR.AA-05 | CPG 2.0 PROTECT |
| CPG2-DE-02 | Review passive captures for cleartext administration (optional) | DETECT | fail | DE.CM-01 | CPG 2.0 DETECT, passive PCAP |
| CPG2-DE-01 | Enable logging on jump hosts, firewalls, and HMIs | DETECT | fail | DE.CM-01, DE.CM-03 | CPG 2.0 DETECT |
| CPG2-GV-01 | Assign a named cybersecurity owner with leadership visibility | GOVERN | fail | GV.RR-01, GV.RR-02 | CPG 2.0 GOVERN |
| CPG2-RS-01 | Keep a current incident response plan and contacts | RESPOND | fail | RS.MA-01, RS.CO-02 | CPG 2.0 RESPOND, incident communication |
| WATER-05 | Know whom to call at the primacy agency and CISA | RESPOND | fail | RS.CO-02 | EPA water checklist theme |
| CPG2-GV-03 | Review privileged access at least annually | GOVERN | fail | GV.OC-05, PR.AA-05 | CPG 2.0 GOVERN, least privilege |
| CPG2-RS-02 | Practice the plan and include ransomware | RESPOND | fail | RS.MA-01, GV.PO-02 | CPG 2.0 RESPOND |
| CPG2-ID-01 | Maintain a living inventory of IT and OT assets | IDENTIFY | pass | ID.AM-01, ID.AM-02 | CPG 2.0 IDENTIFY |
| CPG2-ID-03 | Keep a machine-readable software bill of materials | IDENTIFY | pass | ID.AM-02, ID.SC-04 | CPG 2.0 IDENTIFY, EO 14028 SBOM |
| WATER-01 | List process-control assets used for treatment and distribution | IDENTIFY | pass | ID.AM-01 | EPA water checklist theme |

## Notes

- CivicBaseline is a gap assistant, not a certification.
- Scores weight safety-critical OT assets higher than enterprise IT confidentiality.
- Do not scan live PLCs to produce evidence; use inventories and offline exports.
