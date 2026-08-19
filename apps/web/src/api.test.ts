import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

describe("KubeSentry API client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("submits explicitly supplied YAML and source labels to the local scan endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          scanId: "scan-local-1",
          generatedAt: "2026-08-19T00:00:00Z",
          sourceLabel: "approved-demo.yaml",
          resources: [],
          findings: [],
          summary: {
            riskScore: 0,
            posture: "Reviewed Baseline",
            severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
            resourceCount: 0,
            findingCount: 0,
            policyCoverage: { evaluated: 11, total: 11, profile: "reviewed-baseline / v0.1" }
          }
        }),
        { status: 201, headers: { "Content-Type": "application/json" } }
      )
    );
    vi.stubGlobal("fetch", fetchMock);

    const report = await api.scanManifest("apiVersion: v1\nkind: Pod\nmetadata:\n  name: local", "approved-demo.yaml");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scans",
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          manifestYaml: "apiVersion: v1\nkind: Pod\nmetadata:\n  name: local",
          sourceLabel: "approved-demo.yaml"
        })
      })
    );
    expect(report.summary.policyCoverage.evaluated).toBe(11);
    expect(report.sourceLabel).toBe("approved-demo.yaml");
  });

  it("surfaces a bounded API error message when a local review is rejected", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: "Manifest bundle must contain mapping documents." }), {
          status: 422,
          headers: { "Content-Type": "application/json" }
        })
      )
    );

    await expect(api.scanManifest("- invalid", "approved-demo.yaml")).rejects.toThrow(
      "Manifest bundle must contain mapping documents."
    );
  });
});
