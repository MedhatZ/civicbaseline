# Acceptable Use Policy

CivicBaseline is a **defensive assessment engine**. It evaluates operator-owned evidence (inventories, configuration snapshots, SBOMs, optional passive packet captures) and reports baseline gaps. It is intended for owners, operators, and authorized assessors of systems they are allowed to evaluate.

## Allowed

- Assessing your own critical-infrastructure or lab environment.
- Assessing a customer or partner environment **with written authorization**.
- Using the public fixtures (synthetic water plant, hospital, substation) for training and development.
- Extending rule packs for additional defensive checks.
- Publishing sanitized reports that do not expose live process-control details.

## Not allowed

- Using CivicBaseline, its rule packs, or derivative scripts to **attack, exploit, or disrupt** any system, including systems you do not own.
- Adding exploit payloads, proof-of-concept attack code, default-on active scans of PLCs/RTUs/IEDs, or industrial protocol injection.
- Scanning or capturing traffic on a network without authorization.
- Representing CivicBaseline scores as a legal certification (NERC CIP, HIPAA, IEC 62443, insurance, or grant compliance).
- Using CISA, EPA, HHS, or NIST logos or claiming the tool is a government product.

## Safety for operational technology

Do not point live discovery tools at controllers in order to “feed” CivicBaseline. Export inventories from an existing historian, CMDB, or walk-down. If you supply a PCAP, capture it under a change-control procedure that cannot affect process availability (SPAN/mirror, historian tap, or offline collection).

## Reporting abuse

See [SECURITY.md](SECURITY.md) for vulnerability reports against this project.
