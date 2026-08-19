from fastapi.testclient import TestClient
from kubesentry.main import app


def test_local_fixture_scan_and_metrics_are_available() -> None:
    client = TestClient(app)

    fixtures = client.get("/api/fixtures")
    scan = client.get("/api/scans/demo/insecure-payments")
    metrics = client.get("/metrics")

    assert fixtures.status_code == 200
    assert {fixture["id"] for fixture in fixtures.json()} == {"insecure-payments", "secure-checkout"}
    assert scan.status_code == 200
    assert scan.json()["summary"]["posture"] == "high-risk"
    assert scan.json()["findings"][0]["resource"]["name"] == "legacy-payment-api"
    assert metrics.status_code == 200
    assert "kubesentry_scans_total 1" in metrics.text


def test_manifest_intake_rejects_non_mapping_document() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/scans",
        json={"sourceLabel": "operator-supplied.yaml", "manifestYaml": "- one\n- two\n"},
    )

    assert response.status_code == 422
    assert "must each be a YAML mapping" in response.json()["detail"]
