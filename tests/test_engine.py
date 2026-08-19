from kubesentry.engine import evaluate_manifest_bundle
from kubesentry.fixtures import read_fixture
from kubesentry.manifest import ManifestValidationError, parse_manifest_bundle


def report_for_fixture(fixture_id: str):
    info, manifest_yaml = read_fixture(fixture_id)
    return evaluate_manifest_bundle(parse_manifest_bundle(manifest_yaml), source_label=info.label)


def test_insecure_fixture_produces_explainable_high_risk_findings() -> None:
    report = report_for_fixture("insecure-payments")

    assert report.summary.posture == "high-risk"
    assert report.summary.risk_score == 100
    assert report.summary.finding_count >= 10
    assert {"KSB-001", "KSB-006", "KSB-007", "KSB-011"} <= {finding.policy_id for finding in report.findings}
    privileged = next(finding for finding in report.findings if finding.policy_id == "KSB-001")
    assert privileged.resource.name == "legacy-payment-api"
    assert privileged.evidence_path.endswith("securityContext.privileged")
    assert "Remove privileged mode" in privileged.remediation


def test_hardened_fixture_has_zero_risk_score_and_policy_evidence() -> None:
    report = report_for_fixture("secure-checkout")

    assert report.summary.posture == "reviewed-baseline"
    assert report.summary.risk_score == 0
    assert report.summary.finding_count == 0
    assert report.summary.policy_coverage.evaluated == 11


def test_parser_rejects_non_mapping_documents() -> None:
    try:
        parse_manifest_bundle("- this\n- is\n- a list\n")
    except ManifestValidationError as error:
        assert "must each be a YAML mapping" in str(error)
    else:
        raise AssertionError("The manifest parser accepted a non-mapping document.")
