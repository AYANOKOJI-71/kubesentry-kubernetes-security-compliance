"""Strictly local synthetic KubeSentry fixture access."""

from __future__ import annotations

from pathlib import Path

from .contracts import FixtureInfo

PROJECT_ROOT = Path(__file__).resolve().parents[4]
FIXTURES = {
    "insecure-payments": FixtureInfo(
        id="insecure-payments",
        label="Synthetic payments workload — insecure",
        description="Deliberately unsafe manifest bundle used only to demonstrate evidence-rich findings.",
        expected_posture="high-risk",
    ),
    "secure-checkout": FixtureInfo(
        id="secure-checkout",
        label="Synthetic checkout workload — hardened",
        description="A local baseline example with workload hardening and namespace NetworkPolicy evidence.",
        expected_posture="reviewed-baseline",
    ),
}


def fixture_catalog() -> list[FixtureInfo]:
    """Return fixture metadata without leaking raw manifest text into the UI by default."""
    return list(FIXTURES.values())


def read_fixture(fixture_id: str) -> tuple[FixtureInfo, str]:
    """Read a named fixture from a fixed project path, never a caller-provided path."""
    if fixture_id not in FIXTURES:
        raise KeyError(fixture_id)
    file_name = "demo.yaml"
    fixture_directory = "insecure" if fixture_id.startswith("insecure") else "secure"
    fixture_path = PROJECT_ROOT / "fixtures" / fixture_directory / file_name
    return FIXTURES[fixture_id], fixture_path.read_text(encoding="utf-8")
