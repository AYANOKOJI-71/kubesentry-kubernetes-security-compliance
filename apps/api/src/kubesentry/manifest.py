"""Safe local YAML parsing and Kubernetes resource normalization."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import yaml

from .contracts import ResourceRef

MAX_DOCUMENTS = 100


class ManifestValidationError(ValueError):
    """Raised when an operator-supplied manifest bundle is unsuitable for review."""


def parse_manifest_bundle(manifest_yaml: str) -> list[dict[str, Any]]:
    """Parse a bounded multi-document YAML bundle without executing any content."""
    try:
        raw_documents = list(yaml.safe_load_all(manifest_yaml))
    except yaml.YAMLError as exc:
        raise ManifestValidationError(f"Unable to parse YAML: {exc}") from exc

    documents = [document for document in raw_documents if document is not None]
    if not documents:
        raise ManifestValidationError("The submitted bundle does not contain a YAML resource.")
    if len(documents) > MAX_DOCUMENTS:
        raise ManifestValidationError(f"The submitted bundle exceeds the {MAX_DOCUMENTS}-document review limit.")

    invalid_indexes = [str(index + 1) for index, document in enumerate(documents) if not isinstance(document, dict)]
    if invalid_indexes:
        joined = ", ".join(invalid_indexes)
        raise ManifestValidationError(f"Document(s) {joined} must each be a YAML mapping.")
    return documents


def resource_ref(document: dict[str, Any], document_index: int) -> ResourceRef:
    """Build a display-safe resource reference from a Kubernetes resource mapping."""
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    return ResourceRef(
        api_version=str(document.get("apiVersion") or "unknown"),
        kind=str(document.get("kind") or "Unknown"),
        namespace=str(metadata.get("namespace") or "default"),
        name=str(metadata.get("name") or f"unnamed-document-{document_index + 1}"),
        document_index=document_index,
    )


def is_workload(document: dict[str, Any]) -> bool:
    """Return whether a resource kind embeds a Pod specification suitable for hardening checks."""
    return str(document.get("kind") or "") in {
        "Pod",
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }


def pod_spec(document: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    """Return the embedded Pod specification and evidence-path prefix for a workload."""
    kind = str(document.get("kind") or "")
    spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
    if kind == "Pod":
        return spec, "$.spec"
    if kind == "CronJob":
        job_template = spec.get("jobTemplate") if isinstance(spec.get("jobTemplate"), dict) else {}
        job_spec = job_template.get("spec") if isinstance(job_template.get("spec"), dict) else {}
        template = job_spec.get("template") if isinstance(job_spec.get("template"), dict) else {}
        template_spec = template.get("spec") if isinstance(template.get("spec"), dict) else {}
        return template_spec, "$.spec.jobTemplate.spec.template.spec"
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    template_spec = template.get("spec") if isinstance(template.get("spec"), dict) else {}
    return template_spec, "$.spec.template.spec"


def containers(spec: dict[str, Any]) -> Iterable[tuple[str, int, dict[str, Any]]]:
    """Iterate normal and init containers with their source-list name and index."""
    for list_name in ("containers", "initContainers"):
        values = spec.get(list_name)
        if not isinstance(values, list):
            continue
        for index, container in enumerate(values):
            if isinstance(container, dict):
                yield list_name, index, container
