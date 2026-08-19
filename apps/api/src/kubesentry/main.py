"""FastAPI application for the local-only KubeSentry analyst workflow."""

from __future__ import annotations

from collections import Counter

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware

from .contracts import FixtureInfo, ScanReport, ScanRequest
from .engine import evaluate_manifest_bundle
from .fixtures import fixture_catalog, read_fixture
from .manifest import ManifestValidationError, parse_manifest_bundle

app = FastAPI(
    title="KubeSentry API",
    version="0.1.0",
    description="Defensive, local-only Kubernetes manifest compliance review.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5200", "http://127.0.0.1:5200"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

REPORTS: dict[str, ScanReport] = {}
METRICS = Counter[str]()


def _evaluate(manifest_yaml: str, source_label: str) -> ScanReport:
    try:
        documents = parse_manifest_bundle(manifest_yaml)
    except ManifestValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    report = evaluate_manifest_bundle(documents, source_label=source_label)
    REPORTS[report.scan_id] = report
    METRICS["kubesentry_scans_total"] += 1
    for finding in report.findings:
        METRICS[f"kubesentry_findings_{finding.severity}_total"] += 1
    return report


@app.get("/health")
def health() -> dict[str, str]:
    """Return a non-sensitive health response for local orchestration."""
    return {"status": "ok", "mode": "local-manifest-review"}


@app.get("/api/fixtures", response_model=list[FixtureInfo])
def list_fixtures() -> list[FixtureInfo]:
    """List the bundled synthetic demos available to the analyst console."""
    return fixture_catalog()


@app.get("/api/scans/demo/{fixture_id}", response_model=ScanReport)
def scan_demo_fixture(fixture_id: str) -> ScanReport:
    """Evaluate a fixed, synthetic fixture without reading arbitrary files."""
    try:
        info, manifest_yaml = read_fixture(fixture_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown local fixture.") from exc
    return _evaluate(manifest_yaml, source_label=info.label)


@app.post("/api/scans", response_model=ScanReport, status_code=201)
def scan_manifest(request: ScanRequest) -> ScanReport:
    """Evaluate explicitly supplied YAML text; remote targets and commands are unsupported."""
    return _evaluate(request.manifest_yaml, source_label=request.source_label)


@app.get("/api/scans/{scan_id}", response_model=ScanReport)
def get_scan(scan_id: str) -> ScanReport:
    """Retrieve an in-memory local report by scan identifier."""
    report = REPORTS.get(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan report was not found in this local session.")
    return report


@app.get("/metrics")
def metrics() -> Response:
    """Expose bounded Prometheus-format counters without leaking submitted manifest bodies."""
    lines = [
        "# HELP kubesentry_scans_total Total local manifest scans completed.",
        "# TYPE kubesentry_scans_total counter",
    ]
    lines.append(f"kubesentry_scans_total {METRICS['kubesentry_scans_total']}")
    for severity in ("critical", "high", "medium", "low"):
        metric_name = f"kubesentry_findings_{severity}_total"
        lines.append(f"# TYPE {metric_name} counter")
        lines.append(f"{metric_name} {METRICS[metric_name]}")
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
