from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Rating(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Status(str, Enum):
    pass_ = "pass"
    fail = "fail"
    unknown = "unknown"
    not_applicable = "not_applicable"


class Asset(BaseModel):
    id: str
    name: str
    type: str
    zone: str = "unknown"
    purdue_level: int | None = None
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None
    owner: str | None = None
    criticality: str = "medium"  # safety | high | medium | low
    default_credentials: bool = False
    mfa_enabled: bool | None = None
    logging_enabled: bool | None = None
    internet_exposed: bool = False
    remote_access: bool = False
    protocols: list[str] = Field(default_factory=list)
    managed_by_msp: bool = False
    unused: bool = False
    encrypted_remote: bool | None = None
    patch_status: str | None = None  # current | lagging | unknown
    notes: str | None = None

    @field_validator(
        "id",
        "name",
        "type",
        "zone",
        "vendor",
        "model",
        "firmware",
        "owner",
        "criticality",
        "patch_status",
        "notes",
        mode="before",
    )
    @classmethod
    def _stringify(cls, value: object) -> object:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            text = str(value)
            if isinstance(value, float) and text.endswith(".0"):
                return text[:-2]
            return text
        return value


class FirewallRule(BaseModel):
    id: str
    action: str = "allow"
    src_zone: str
    dst_zone: str
    service: str = "any"
    enabled: bool = True
    notes: str | None = None


class Account(BaseModel):
    id: str
    name: str
    role: str = "user"
    shared: bool = False
    default_password: bool = False
    mfa: bool = False
    disabled: bool = False
    asset_id: str | None = None
    last_review: str | None = None

    @field_validator("name", "role", "last_review", mode="before")
    @classmethod
    def _stringify(cls, value: object) -> object:
        if isinstance(value, (int, float)):
            return str(value)
        return value


class BackupPolicy(BaseModel):
    ot_backups_configured: bool = False
    ot_backups_tested: bool = False
    offline_or_immutable: bool = False
    restore_rto_hours: int | None = None
    includes_hmi_and_plc_logic: bool = False


class IncidentPolicy(BaseModel):
    plan_exists: bool = False
    contacts_current: bool = False
    communicates_to_regulators: bool = False
    tabletop_in_last_year: bool = False
    ransomware_playbook: bool = False


class GovernancePolicy(BaseModel):
    cyber_role_assigned: bool = False
    board_or_council_briefed: bool = False
    msp_contract_security_clauses: bool = False
    vendor_remote_access_logged: bool = False
    least_privilege_review: bool = False
    security_training: bool = False


class HealthcarePolicy(BaseModel):
    ehr_backup_tested: bool = False
    ba_agreements: bool = False
    medical_device_inventory: bool = False
    emergency_downtime_procedures: bool = False


class EnergyPolicy(BaseModel):
    der_remote_access_controlled: bool = False
    relay_settings_change_control: bool = False
    adms_or_scada_segmentation: bool = False
    supply_chain_for_ied_firmware: bool = False


class Policies(BaseModel):
    backup: BackupPolicy = Field(default_factory=BackupPolicy)
    incident: IncidentPolicy = Field(default_factory=IncidentPolicy)
    governance: GovernancePolicy = Field(default_factory=GovernancePolicy)
    healthcare: HealthcarePolicy = Field(default_factory=HealthcarePolicy)
    energy: EnergyPolicy = Field(default_factory=EnergyPolicy)


class ZonePair(BaseModel):
    src: str
    dst: str
    allowed: bool = False


class SoftwareComponent(BaseModel):
    name: str
    version: str | None = None
    type: str | None = None
    purl: str | None = None
    cpe: str | None = None
    cves: list[str] = Field(default_factory=list)
    supplier: str | None = None
    asset_id: str | None = None

    @field_validator("name", "version", "type", "purl", "cpe", "supplier", "asset_id", mode="before")
    @classmethod
    def _stringify(cls, value: object) -> object:
        if isinstance(value, (int, float)):
            return str(value)
        return value


class PcapFlow(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "tcp"
    cleartext: bool = False
    src_zone: str | None = None
    dst_zone: str | None = None


class EvidenceBundle(BaseModel):
    organization: str = "Unnamed operator"
    sector: str = "water"
    assets: list[Asset] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    accounts: list[Account] = Field(default_factory=list)
    policies: Policies = Field(default_factory=Policies)
    ip_zones: dict[str, str] = Field(default_factory=dict)
    software: list[SoftwareComponent] = Field(default_factory=list)
    sbom_present: bool = False
    pcap_flows: list[PcapFlow] = Field(default_factory=list)
    kev_cves: set[str] = Field(default_factory=set)
    extra: dict[str, Any] = Field(default_factory=dict)


class CheckSpec(BaseModel):
    id: str
    type: str
    field: str | None = None
    expected: Any = None
    where: dict[str, Any] = Field(default_factory=dict)
    required_fields: list[str] = Field(default_factory=list)
    forbid_pairs: list[list[str]] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    fail_message: str = ""
    unknown_if_empty: bool = False


class RuleSpec(BaseModel):
    id: str
    title: str
    function: str
    summary: str = ""
    nist_csf: list[str] = Field(default_factory=list)
    mitre_ics: list[str] = Field(default_factory=list)
    overlays: list[str] = Field(default_factory=list)
    cost: Rating = Rating.medium
    impact: Rating = Rating.medium
    ease: Rating = Rating.medium
    ot_weight: float = 1.0
    remediation: list[str] = Field(default_factory=list)
    checks: list[CheckSpec] = Field(default_factory=list)


class PackSpec(BaseModel):
    id: str
    name: str
    description: str = ""
    includes: list[str] = Field(default_factory=list)


class CheckResult(BaseModel):
    check_id: str
    status: Status
    message: str
    evidence_refs: list[str] = Field(default_factory=list)


class RuleResult(BaseModel):
    rule: RuleSpec
    status: Status
    checks: list[CheckResult]
    score_weight: float
    priority: float
    failed_assets: list[str] = Field(default_factory=list)


class AssessmentResult(BaseModel):
    pack_id: str
    pack_name: str
    organization: str
    sector: str
    score: float
    passed: int
    failed: int
    unknown: int
    not_applicable: int
    rules: list[RuleResult]
    generated_notes: list[str] = Field(default_factory=list)
