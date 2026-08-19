"""Typed API and policy-engine contracts for KubeSentry."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


def to_camel(value: str) -> str:
    """Convert internal snake-case model fields to the API's camel-case contract."""
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class ApiModel(BaseModel):
    """Base response model using stable camel-case JSON keys."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


Severity = Literal["critical", "high", "medium", "low"]


class ResourceRef(ApiModel):
    api_version: str
    kind: str
    namespace: str
    name: str
    document_index: int


class Finding(ApiModel):
    id: str
    policy_id: str
    severity: Severity
    title: str
    rationale: str
    remediation: str
    evidence_path: str
    resource: ResourceRef


class PolicyCoverage(ApiModel):
    evaluated: int
    total: int
    profile: str


class ScanSummary(ApiModel):
    risk_score: int = Field(ge=0, le=100)
    posture: str
    severity_counts: dict[str, int]
    resource_count: int
    finding_count: int
    policy_coverage: PolicyCoverage


class ScanReport(ApiModel):
    scan_id: str
    generated_at: datetime
    source_label: str
    resources: list[ResourceRef]
    findings: list[Finding]
    summary: ScanSummary


class ScanRequest(ApiModel):
    manifest_yaml: str = Field(min_length=1, max_length=700_000)
    source_label: str = Field(default="operator-supplied.yaml", min_length=1, max_length=120)


class FixtureInfo(ApiModel):
    id: str
    label: str
    description: str
    expected_posture: str


class ErrorDetail(ApiModel):
    detail: str
