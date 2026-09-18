# Impact KPIs (collect from day one)

These metrics turn CivicBaseline from “a GitHub repo” into **prong 2 evidence** for an NIW petition. Update `docs/en/impact-log.md` when numbers change. None of this is legal advice.

## Product completeness

| KPI | How to measure | 12-month target |
| --- | --- | --- |
| Unique rules | `scripts/release_artifacts.py` snapshot | Cover remaining high-value CPG 2.0 themes as CISA publishes clarifications |
| Sector packs | water, healthcare, energy | Keep three sectors; add chemical SSG only if an operator asks |
| Fixture regressions | `pytest` in CI | Zero failing tests on `main` |
| Safe-by-default | Code review: no active PLC scan | Hold the AUP |

## Adoption (national interest)

| KPI | How to measure | Notes |
| --- | --- | --- |
| Releases | Git tags + GH Release | Date every artifact |
| Downloads / clones | GitHub insights | Qualitative if numbers are small |
| Independent users | Issues, forks, thank-you letters | One rural water or hospital letter outweighs stars |
| Education | Course or lab that runs `fixtures/water-plant` | Community college / university OT lab |
| Talks | S4x, Black Hat Arsenal (defensive), RSA, AWWA, state rural water | Slides + recording |

## Risk reduction (method, not marketing)

On the **synthetic** water fixture, track time-to-close for “high ease” failed rules after a documented hardening pass (`fixtures/water-plant-hardened`). Do not invent live-plant statistics you cannot defend.

## Petition hygiene

Save PDFs of: this table, release notes, CI badges, conference acceptance mail, and operator letters. Counsel, not the README, decides what is filed.
