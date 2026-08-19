"""KubeSentry defensive Kubernetes manifest review service."""

from .engine import evaluate_manifest_bundle

__all__ = ["evaluate_manifest_bundle"]
