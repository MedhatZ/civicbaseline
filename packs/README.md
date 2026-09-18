# Rule packs

YAML under this tree is **policy as code**. IDs such as `CPG2-PR-01` are CivicBaseline identifiers. They are aligned to public CISA CPG 2.0 *themes* (NIST CSF 2.0 functions, small-operator outcomes) and are **not** official CISA control numbers.

Do not paste copyrighted CPG, EPA, or HHS checklist text into these files. Write original titles, summaries, and remediation.

| Directory | Loaded by |
| --- | --- |
| `cpg2/` | packs `cpg2`, `water`, `healthcare`, `energy` |
| `water-epa/` | pack `water` |
| `healthcare-ssg/` | pack `healthcare` |
| `energy-der/` | pack `energy` |

Composite packs (`water`, `healthcare`, `energy`) list `includes` in their `pack.yaml`.
