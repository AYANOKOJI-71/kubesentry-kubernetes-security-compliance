export type Severity = "critical" | "high" | "medium" | "low";

export interface ResourceRef {
  apiVersion: string;
  kind: string;
  namespace: string;
  name: string;
  documentIndex: number;
}

export interface Finding {
  id: string;
  policyId: string;
  severity: Severity;
  title: string;
  rationale: string;
  remediation: string;
  evidencePath: string;
  resource: ResourceRef;
}

export interface ScanReport {
  scanId: string;
  generatedAt: string;
  sourceLabel: string;
  resources: ResourceRef[];
  findings: Finding[];
  summary: {
    riskScore: number;
    posture: string;
    severityCounts: Record<Severity, number>;
    resourceCount: number;
    findingCount: number;
    policyCoverage: { evaluated: number; total: number; profile: string };
  };
}

export interface FixtureInfo {
  id: string;
  label: string;
  description: string;
  expectedPosture: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers }
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({ detail: "Unable to contact the local review API." }))) as {
      detail?: string;
    };
    throw new Error(body.detail ?? "Unable to complete the review.");
  }
  return response.json() as Promise<T>;
}

export const api = {
  fixtures: () => request<FixtureInfo[]>("/api/fixtures"),
  scanFixture: (fixtureId: string) => request<ScanReport>(`/api/scans/demo/${fixtureId}`),
  scanManifest: (manifestYaml: string, sourceLabel: string) =>
    request<ScanReport>("/api/scans", {
      method: "POST",
      body: JSON.stringify({ manifestYaml, sourceLabel })
    })
};
