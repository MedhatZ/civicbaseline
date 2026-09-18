# Contributing

Thank you for helping raise the cybersecurity baseline of small U.S. critical-infrastructure operators.

## Ground rules

1. Read [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md). Defensive contributions only.
2. New checks need: a YAML rule, a fixture that fails and a fixture path that passes (or a unit test), and original wording (do not paste copyrighted CPG/EPA/HHS text).
3. Do not add network clients that scan controllers. Evidence parsers read files.
4. Keep dependencies minimal. Prefer the standard library.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
civicbaseline assess --pack water --evidence fixtures/water-plant --out reports/water
```

## Rule pack style

- IDs: `CPG2-xx-nn`, `WATER-nn`, `HEALTH-nn`, `ENERGY-nn`.
- Map `nist_csf` and optional `mitre_ics` technique IDs.
- Set `cost`, `impact`, and `ease` to `low`, `medium`, or `high` (CPG-style prioritization, original ratings).
- Remediation steps must be safe: backup, maintenance window, vendor procedure — never “exploit to prove.”

## Pull requests

- Include tests.
- Run the water fixture and attach a snippet of the markdown report if you change scoring.
- Sign off that you have the right to submit the work under Apache-2.0.
