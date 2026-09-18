# Evidence directory schema

All files are optional except that an empty directory yields a failing inventory. Use UTF-8 YAML/JSON. Never put live process setpoints or badge secrets in a public repo.

## inventory.yaml

```yaml
organization: Example Water
sector: water   # water | healthcare | energy | other
assets:
  - id: plc-1
    name: High-service pump PLC
    type: plc    # plc, rtu, ied, hmi, historian, jump_host, firewall, vpn, gateway, recloser, workstation
    zone: ot     # ot, it, dmz, safety, control, internet
    purdue_level: 1
    vendor: OEM
    firmware: "1.2.3"
    owner: operations
    criticality: safety  # safety | high | medium | low
    default_credentials: false
    mfa_enabled: false
    logging_enabled: true
    internet_exposed: false
    remote_access: false
    encrypted_remote: true
    protocols: [modbus]
    managed_by_msp: false
```

## firewall.yaml

Zone names should match `asset.zone`. CivicBaseline does not parse vendor ACL syntax in v0.1; export a simplified allow/deny list.

## policies.yaml

Nested objects: `backup`, `incident`, `governance`, `healthcare`, `energy`. Booleans default to false if omitted.

## sbom.json

CycloneDX 1.4/1.5 JSON or SPDX 2.3 JSON. CVE identifiers in CycloneDX `vulnerabilities[].id` are correlated with KEV **IDs only**.

## traffic.pcap

Classic pcap (not pcapng) Ethernet/IPv4/TCP-or-UDP. Optional. Capture from a mirror port under change control.
