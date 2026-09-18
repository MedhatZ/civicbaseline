from __future__ import annotations

from civicbaseline.models import AssessmentResult, Asset, Rating, RuleResult, Status

_RATING_VALUE = {Rating.low: 1.0, Rating.medium: 2.0, Rating.high: 3.0}

_CRITICALITY_VALUE = {
    "safety": 2.2,
    "high": 1.6,
    "medium": 1.0,
    "low": 0.7,
}


def ot_weight_for_assets(assets: list[Asset]) -> float:
    if not assets:
        return 1.0
    return max(_CRITICALITY_VALUE.get(a.criticality, 1.0) for a in assets)


def priority_score(rule, status: Status, weight: float) -> float:
    if status != Status.fail:
        return 0.0
    impact = _RATING_VALUE[rule.impact]
    # Easier fixes bubble up for small operators (CPG-style "ease of implementation").
    ease = _RATING_VALUE[rule.ease]
    ease_boost = (4.0 - ease) / 3.0
    return round(impact * ease_boost * weight, 3)


def rollup_status(statuses: list[Status]) -> Status:
    if not statuses:
        return Status.unknown
    if any(s == Status.fail for s in statuses):
        return Status.fail
    if all(s == Status.not_applicable for s in statuses):
        return Status.not_applicable
    if all(s in {Status.pass_, Status.not_applicable} for s in statuses):
        return Status.pass_
    if all(s in {Status.unknown, Status.not_applicable} for s in statuses):
        return Status.unknown
    if any(s == Status.unknown for s in statuses) and all(
        s in {Status.pass_, Status.unknown, Status.not_applicable} for s in statuses
    ):
        return Status.unknown
    return Status.unknown


def summarize(pack_id: str, pack_name: str, organization: str, sector: str, rules: list[RuleResult]) -> AssessmentResult:
    countable = [r for r in rules if r.status in {Status.pass_, Status.fail}]
    weighted_total = sum(r.score_weight for r in countable) or 1.0
    weighted_pass = sum(r.score_weight for r in countable if r.status == Status.pass_)
    score = round(100.0 * weighted_pass / weighted_total, 1)
    return AssessmentResult(
        pack_id=pack_id,
        pack_name=pack_name,
        organization=organization,
        sector=sector,
        score=score,
        passed=sum(1 for r in rules if r.status == Status.pass_),
        failed=sum(1 for r in rules if r.status == Status.fail),
        unknown=sum(1 for r in rules if r.status == Status.unknown),
        not_applicable=sum(1 for r in rules if r.status == Status.not_applicable),
        rules=sorted(rules, key=lambda r: (-r.priority, r.rule.id)),
        generated_notes=[
            "CivicBaseline is a gap assistant, not a certification.",
            "Scores weight safety-critical OT assets higher than enterprise IT confidentiality.",
            "Do not scan live PLCs to produce evidence; use inventories and offline exports.",
        ],
    )
