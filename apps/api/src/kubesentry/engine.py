"""Deterministic, side-effect-free Kubernetes manifest hardening checks."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from .contracts import Finding, PolicyCoverage, ResourceRef, ScanReport, ScanSummary
from .manifest import containers, is_workload, pod_spec, resource_ref

POLICY_IDS = (
    "KSB-001",
    "KSB-002",
    "KSB-003",
    "KSB-004",
    "KSB-005",
    "KSB-006",
    "KSB-007",
    "KSB-008",
    "KSB-009",
    "KSB-010",
    "KSB-011",
)
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _find(
    *,
    policy_id: str,
    severity: str,
    title: str,
    rationale: str,
    remediation: str,
    evidence_path: str,
    resource: ResourceRef,
) -> Finding:
    return Finding(
        id=f"{policy_id}:{resource.document_index}:{evidence_path}",
        policy_id=policy_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        rationale=rationale,
        remediation=remediation,
        evidence_path=evidence_path,
        resource=resource,
    )


def _container_path(prefix: str, list_name: str, index: int, suffix: str) -> str:
    return f"{prefix}.{list_name}[{index}]{suffix}"


def _image_is_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    final_component = image.rsplit("/", 1)[-1]
    return ":" in final_component and not final_component.endswith(":latest")


def _effective_security_context(pod_security: dict[str, Any], container: dict[str, Any]) -> dict[str, Any]:
    """Merge pod defaults with explicit container fields for read-only inspection."""
    effective = dict(pod_security)
    effective.update(_mapping(container.get("securityContext")))
    return effective


def _evaluate_workload(document: dict[str, Any], index: int) -> list[Finding]:
    resource = resource_ref(document, index)
    embedded = pod_spec(document)
    if embedded is None:
        return []
    spec, prefix = embedded
    findings: list[Finding] = []
    pod_security = _mapping(spec.get("securityContext"))

    for field in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(field) is True:
            findings.append(
                _find(
                    policy_id="KSB-006",
                    severity="high",
                    title="Host namespace sharing is enabled",
                    rationale=f"{field} weakens workload isolation by sharing a host namespace.",
                    remediation=(
                        "Disable host namespace sharing unless this is a documented, trusted infrastructure workload."
                    ),
                    evidence_path=f"{prefix}.{field}",
                    resource=resource,
                )
            )

    volumes = spec.get("volumes") if isinstance(spec.get("volumes"), list) else []
    for volume_index, volume in enumerate(volumes):
        if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
            findings.append(
                _find(
                    policy_id="KSB-007",
                    severity="high",
                    title="HostPath volume is mounted",
                    rationale="HostPath can expose host filesystems to a workload.",
                    remediation="Use a CSI, projected, config, secret, or persistent volume instead of HostPath.",
                    evidence_path=f"{prefix}.volumes[{volume_index}].hostPath",
                    resource=resource,
                )
            )

    if spec.get("automountServiceAccountToken") is not False:
        findings.append(
            _find(
                    policy_id="KSB-010",
                    severity="medium",
                    title="Default service-account token mounting is enabled",
                    rationale=(
                        "Automatic token mounting expands the credential surface for workloads that do not need "
                        "Kubernetes API access."
                    ),
                    remediation=(
                        "Set automountServiceAccountToken: false, then opt in only for workloads with a justified API "
                        "requirement."
                    ),
                evidence_path=f"{prefix}.automountServiceAccountToken",
                resource=resource,
            )
        )

    for list_name, container_index, container in containers(spec):
        container_prefix = _container_path(prefix, list_name, container_index, "")
        security = _effective_security_context(pod_security, container)
        security_path = f"{container_prefix}.securityContext"

        if security.get("privileged") is True:
            findings.append(
                _find(
                    policy_id="KSB-001",
                    severity="critical",
                    title="Container runs in privileged mode",
                    rationale="Privileged containers bypass important container isolation mechanisms.",
                    remediation="Remove privileged mode and use only narrowly justified capabilities.",
                    evidence_path=f"{security_path}.privileged",
                    resource=resource,
                )
            )
        if security.get("allowPrivilegeEscalation") is not False:
            findings.append(
                _find(
                    policy_id="KSB-002",
                    severity="high",
                    title="Privilege escalation is not explicitly disabled",
                    rationale=(
                        "The container may retain a path to gain additional privileges through executable file modes."
                    ),
                    remediation="Set securityContext.allowPrivilegeEscalation: false.",
                    evidence_path=f"{security_path}.allowPrivilegeEscalation",
                    resource=resource,
                )
            )
        if security.get("runAsNonRoot") is not True or security.get("runAsUser") == 0:
            findings.append(
                _find(
                    policy_id="KSB-003",
                    severity="high",
                    title="Container can run as root",
                    rationale=(
                        "The workload does not provide sufficient evidence that the container will run as a "
                        "non-root user."
                    ),
                    remediation=(
                        "Set runAsNonRoot: true and use a non-zero runAsUser where appropriate for the image."
                    ),
                    evidence_path=f"{security_path}.runAsNonRoot",
                    resource=resource,
                )
            )
        seccomp = _mapping(security.get("seccompProfile"))
        if seccomp.get("type") not in {"RuntimeDefault", "Localhost"}:
            findings.append(
                _find(
                    policy_id="KSB-004",
                    severity="medium",
                    title="Effective seccomp profile is missing",
                    rationale="No RuntimeDefault or Localhost seccomp profile is configured for this container.",
                    remediation=(
                        "Set a pod-level or container-level seccompProfile.type to RuntimeDefault or an approved "
                        "Localhost profile."
                    ),
                    evidence_path=f"{security_path}.seccompProfile.type",
                    resource=resource,
                )
            )
        capabilities = _mapping(security.get("capabilities"))
        dropped = capabilities.get("drop") if isinstance(capabilities.get("drop"), list) else []
        if "ALL" not in dropped:
            findings.append(
                _find(
                    policy_id="KSB-005",
                    severity="medium",
                    title="Container does not drop all Linux capabilities",
                    rationale="No evidence shows that the container starts from a minimal capability set.",
                    remediation="Set capabilities.drop: [\"ALL\"] and add only the explicitly required capability.",
                    evidence_path=f"{security_path}.capabilities.drop",
                    resource=resource,
                )
            )

        image = str(container.get("image") or "")
        if not _image_is_pinned(image):
            findings.append(
                _find(
                    policy_id="KSB-008",
                    severity="medium",
                    title="Container image is not pinned to an approved release",
                    rationale="An untagged or latest-tag image can resolve to different content over time.",
                    remediation=(
                        "Use an approved explicit version tag and consider a digest for immutable release review."
                    ),
                    evidence_path=f"{container_prefix}.image",
                    resource=resource,
                )
            )

        resources = _mapping(container.get("resources"))
        requests = _mapping(resources.get("requests"))
        limits = _mapping(resources.get("limits"))
        if not requests or not limits:
            findings.append(
                _find(
                    policy_id="KSB-009",
                    severity="low",
                    title="Container resource controls are incomplete",
                    rationale=(
                        "Requests and limits are missing, reducing schedulability and resource-containment evidence."
                    ),
                    remediation="Define CPU and memory requests and limits appropriate to the workload.",
                    evidence_path=f"{container_prefix}.resources",
                    resource=resource,
                )
            )
    return findings


def _network_policy_findings(documents: list[dict[str, Any]]) -> list[Finding]:
    resource_refs = [resource_ref(document, index) for index, document in enumerate(documents)]
    policy_namespaces = {
        reference.namespace
        for reference in resource_refs
        if reference.kind == "NetworkPolicy" and reference.api_version.startswith("networking.k8s.io/")
    }
    findings: list[Finding] = []
    for document_index, document in enumerate(documents):
        if not is_workload(document):
            continue
        reference = resource_ref(document, document_index)
        if reference.namespace not in policy_namespaces:
            findings.append(
                _find(
                    policy_id="KSB-011",
                    severity="medium",
                    title="Network-isolation evidence is missing from the bundle",
                    rationale="No NetworkPolicy for this workload namespace appears in the submitted manifest bundle.",
                    remediation=(
                        "Add reviewed ingress and egress NetworkPolicy resources and verify enforcement by "
                        "the target CNI."
                    ),
                    evidence_path="$.metadata.namespace",
                    resource=reference,
                )
            )
    return findings


def _posture(score: int) -> str:
    if score == 0:
        return "reviewed-baseline"
    if score <= 20:
        return "needs-hardening"
    if score <= 50:
        return "elevated-risk"
    return "high-risk"


def evaluate_manifest_bundle(
    documents: list[dict[str, Any]],
    source_label: str,
    now: Callable[[], datetime] | None = None,
) -> ScanReport:
    """Evaluate an already parsed manifest bundle without any external side effects."""
    findings = [
        finding
        for index, document in enumerate(documents)
        if is_workload(document)
        for finding in _evaluate_workload(document, index)
    ]
    findings.extend(_network_policy_findings(documents))
    severity_counts = Counter(finding.severity for finding in findings)
    score = min(100, sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings))
    generated_at = (now or (lambda: datetime.now(UTC)))()
    return ScanReport(
        scan_id=str(uuid4()),
        generated_at=generated_at,
        source_label=source_label,
        resources=[
            resource_ref(document, index)
            for index, document in enumerate(documents)
        ],
        findings=sorted(
            findings,
            key=lambda finding: (
                -SEVERITY_WEIGHTS[finding.severity],
                finding.policy_id,
                finding.id,
            ),
        ),
        summary=ScanSummary(
            risk_score=score,
            posture=_posture(score),
            severity_counts={
                severity: severity_counts.get(severity, 0)
                for severity in ("critical", "high", "medium", "low")
            },
            resource_count=len(documents),
            finding_count=len(findings),
            policy_coverage=PolicyCoverage(
                evaluated=len(POLICY_IDS),
                total=len(POLICY_IDS),
                profile="reviewed-baseline",
            ),
        ),
    )
