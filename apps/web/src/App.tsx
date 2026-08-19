import { FormEvent, useEffect, useMemo, useState } from "react";
import { api, Finding, FixtureInfo, ScanReport, Severity } from "./api";

const severityOrder: Severity[] = ["critical", "high", "medium", "low"];

const icons = {
  shield: "◈",
  bolt: "↯",
  arrow: "→",
  check: "✓",
  warning: "!"
};

function formatPosture(value: string): string {
  return value.replaceAll("-", " ");
}

function scoreTone(score: number): string {
  if (score === 0) return "calm";
  if (score <= 20) return "watch";
  if (score <= 50) return "elevated";
  return "critical";
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className={`finding finding--${finding.severity}`}>
      <div className="finding__topline">
        <span className={`severity severity--${finding.severity}`}>{finding.severity}</span>
        <span className="policy-id">{finding.policyId}</span>
        <span className="finding__resource">
          {finding.resource.namespace}/{finding.resource.name}
        </span>
      </div>
      <h3>{finding.title}</h3>
      <p>{finding.rationale}</p>
      <div className="evidence">
        <span>EVIDENCE</span>
        <code>{finding.evidencePath}</code>
      </div>
      <div className="remediation">
        <span>{icons.arrow}</span>
        <p>{finding.remediation}</p>
      </div>
    </article>
  );
}

function App() {
  const [fixtures, setFixtures] = useState<FixtureInfo[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [activeFixture, setActiveFixture] = useState("insecure-payments");
  const [manifestYaml, setManifestYaml] = useState("");
  const [sourceLabel, setSourceLabel] = useState("operator-supplied.yaml");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showManifestReview, setShowManifestReview] = useState(false);

  const loadFixture = async (fixtureId: string) => {
    setLoading(true);
    setError(null);
    try {
      setReport(await api.scanFixture(fixtureId));
      setActiveFixture(fixtureId);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "The local review API returned an unknown error.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void (async () => {
      try {
        const availableFixtures = await api.fixtures();
        setFixtures(availableFixtures);
        await loadFixture("insecure-payments");
      } catch (requestError) {
        setError(requestError instanceof Error ? requestError.message : "Unable to load the local review workspace.");
        setLoading(false);
      }
    })();
  }, []);

  const totalFindings = report?.summary.findingCount ?? 0;
  const highPriorityFindings = useMemo(
    () => report?.findings.filter((finding) => finding.severity === "critical" || finding.severity === "high") ?? [],
    [report]
  );

  const submitManifest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!manifestYaml.trim()) {
      setError("Paste an explicitly authorized YAML manifest bundle before starting a local review.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      setReport(await api.scanManifest(manifestYaml, sourceLabel));
      setActiveFixture("custom");
      setShowManifestReview(false);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to review the supplied manifest.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand__mark">{icons.shield}</div>
          <div>
            <span className="eyebrow">CYBER INVASION ARMY</span>
            <h1>KubeSentry</h1>
          </div>
        </div>

        <div className="mode-card">
          <span className="pulse" />
          <div>
            <strong>Review mode</strong>
            <p>Local manifests only</p>
          </div>
        </div>

        <nav aria-label="Review sources">
          <p className="nav-label">DEMONSTRATION BUNDLES</p>
          {fixtures.map((fixture) => (
            <button
              className={`fixture-button ${activeFixture === fixture.id ? "fixture-button--active" : ""}`}
              key={fixture.id}
              onClick={() => void loadFixture(fixture.id)}
              type="button"
            >
              <span className="fixture-button__icon">{fixture.id.startsWith("secure") ? icons.check : icons.warning}</span>
              <span>
                <strong>{fixture.label.split(" — ")[0]}</strong>
                <small>{fixture.expectedPosture.replaceAll("-", " ")}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar__footer">
          <span>POLICY SET</span>
          <strong>reviewed-baseline / v0.1</strong>
          <p>No cluster discovery. No changes. No credentials retained.</p>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">AUTHORIZED MANIFEST REVIEW</p>
            <h2>Evidence before enforcement.</h2>
          </div>
          <div className="topbar__actions">
            <span className="api-status"><i /> API connected</span>
            <button className="outline-button" onClick={() => setShowManifestReview(true)} type="button">
              Review YAML <span>{icons.arrow}</span>
            </button>
          </div>
        </header>

        {error && <div className="error-banner">{error}</div>}

        {showManifestReview && (
          <section className="manifest-panel" aria-label="Review supplied manifest">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">EXPLICITLY SUPPLIED CONTENT</p>
                <h3>Review a local YAML bundle</h3>
              </div>
              <button className="text-button" onClick={() => setShowManifestReview(false)} type="button">
                Cancel
              </button>
            </div>
            <form onSubmit={submitManifest}>
              <label>
                Source label
                <input value={sourceLabel} onChange={(event) => setSourceLabel(event.target.value)} maxLength={120} />
              </label>
              <label>
                Kubernetes YAML
                <textarea
                  value={manifestYaml}
                  onChange={(event) => setManifestYaml(event.target.value)}
                  placeholder="Paste a manifest bundle you own or are explicitly authorized to review."
                  rows={8}
                />
              </label>
              <div className="form-footer">
                <p>Submitted text is parsed locally. KubeSentry does not connect to clusters or execute YAML.</p>
                <button className="primary-button" type="submit">
                  Run local review {icons.bolt}
                </button>
              </div>
            </form>
          </section>
        )}

        {loading && !report ? (
          <section className="empty-state">
            <span className="loading-orb" />
            <p>Preparing the local evidence workspace…</p>
          </section>
        ) : report ? (
          <>
            <section className="hero-grid">
              <article className={`posture-card posture-card--${scoreTone(report.summary.riskScore)}`}>
                <div className="posture-card__header">
                  <span>POSTURE SIGNAL</span>
                  <span className="live-dot">LIVE REPORT</span>
                </div>
                <div className="posture-score">
                  <strong>{report.summary.riskScore}</strong>
                  <span>/100</span>
                </div>
                <h3>{formatPosture(report.summary.posture)}</h3>
                <p>
                  {totalFindings === 0
                    ? "No baseline findings were identified in this submitted bundle. Human context still governs deployment decisions."
                    : `${totalFindings} evidence-backed policy findings require review before this bundle is promoted.`}
                </p>
                <div className="score-line"><span style={{ width: `${Math.max(report.summary.riskScore, 3)}%` }} /></div>
              </article>

              <article className="source-card">
                <p className="eyebrow">CURRENT BUNDLE</p>
                <h3>{report.sourceLabel}</h3>
                <dl>
                  <div><dt>Resources</dt><dd>{report.summary.resourceCount}</dd></div>
                  <div><dt>Policies</dt><dd>{report.summary.policyCoverage.evaluated}/{report.summary.policyCoverage.total}</dd></div>
                  <div><dt>High priority</dt><dd>{highPriorityFindings.length}</dd></div>
                </dl>
                <p className="source-card__note">Created {new Date(report.generatedAt).toLocaleTimeString()}</p>
              </article>

              <article className="coverage-card">
                <p className="eyebrow">SEVERITY DISTRIBUTION</p>
                <div className="severity-list">
                  {severityOrder.map((severity) => (
                    <div key={severity}>
                      <span className={`severity severity--${severity}`}>{severity}</span>
                      <strong>{report.summary.severityCounts[severity]}</strong>
                      <i style={{ width: `${Math.min(100, (report.summary.severityCounts[severity] / Math.max(totalFindings, 1)) * 100)}%` }} />
                    </div>
                  ))}
                </div>
              </article>
            </section>

            <section className="content-grid">
              <section className="findings-section">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">REVIEW QUEUE</p>
                    <h3>Evidence-backed findings</h3>
                  </div>
                  <span className="count-pill">{totalFindings} finding{totalFindings === 1 ? "" : "s"}</span>
                </div>
                {totalFindings === 0 ? (
                  <div className="clear-state">
                    <span>{icons.check}</span>
                    <div><strong>Baseline controls present</strong><p>This bundle carries the local review evidence used by the current profile.</p></div>
                  </div>
                ) : (
                  <div className="finding-list">{report.findings.map((finding) => <FindingCard finding={finding} key={finding.id} />)}</div>
                )}
              </section>

              <aside className="context-rail">
                <section className="rail-card">
                  <p className="eyebrow">RESOURCE INVENTORY</p>
                  <div className="resource-list">
                    {report.resources.map((resource) => (
                      <div className="resource-item" key={`${resource.documentIndex}-${resource.kind}-${resource.name}`}>
                        <span>{resource.kind.slice(0, 2).toUpperCase()}</span>
                        <div><strong>{resource.kind}/{resource.name}</strong><small>{resource.namespace} · document {resource.documentIndex + 1}</small></div>
                      </div>
                    ))}
                  </div>
                </section>
                <section className="rail-card rail-card--note">
                  <p className="eyebrow">SCOPE CONTROL</p>
                  <h4>Advisory analysis only.</h4>
                  <p>KubeSentry evaluates only the manifest text supplied to this session. It does not discover, scan, or change Kubernetes clusters.</p>
                </section>
              </aside>
            </section>
          </>
        ) : null}
      </section>
    </main>
  );
}

export default App;
