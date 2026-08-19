# Demonstration Verification

## Local analyst-console check

The KubeSentry React console was opened against the local FastAPI service through the temporary development preview on 19 August 2026. The supplied **Synthetic payments workload — insecure** bundle rendered successfully and displayed the expected review-only posture.

| Verification point | Observed result |
|---|---|
| Scope control | The sidebar and scope-control card state that the service reviews local manifests only and does not discover, scan, or change clusters. |
| API workflow | The console reported an active API connection and loaded the fixture-backed report. |
| Risk summary | The synthetic insecure bundle showed score **100/100**, posture **High Risk**, **17** evidence-backed findings, three resources, and 11/11 policies evaluated. |
| Finding evidence | The review queue showed severity, policy ID, namespaced resource, JSON-style evidence path, rationale, and a remediation statement. |
| Analyst context | The resource inventory and severity distribution were visible alongside the review queue. |
| Responsive structure | The desktop console preserved a readable sidebar, summary band, finding queue, and context rail without clipping in the recorded preview. |

## Hardened fixture and intake control

The console was also switched to **Synthetic checkout workload — hardened**. It rendered a **0/100** Reviewed Baseline posture, zero findings in every severity band, three resources, 11/11 policies evaluated, a baseline-controls confirmation, and the expected NetworkPolicy entry in the resource inventory.

The **Review YAML** action opened a form requiring a source label and manifest text. The interface explicitly states that submitted text is parsed locally and that KubeSentry does not connect to clusters or execute YAML. This gives an authorized operator a deliberate local review path without exposing remote-target fields or execution controls.

For the intake check, the source was labeled `approved-local-demo.yaml` and a synthetic hardened Pod manifest was pasted into the form. The manifest uses no live endpoint, credential, client, or production-cluster data.

Submission completed successfully against the local API. The report inventoried one Pod and evaluated 11/11 policies. It assigned an **8/100 Needs Hardening** posture with one medium-severity KSB-011 finding: **Network-isolation evidence is missing from the bundle**. The result named the affected local resource, showed the evidence path `$.metadata.namespace`, explained that no NetworkPolicy for the workload namespace appeared in the supplied bundle, and recommended adding reviewed ingress and egress NetworkPolicy resources before checking the target CNI. No cluster operation occurred.

The synthetic insecure bundle is deliberately constructed for demonstration only. It contains no real clusters, credentials, customer information, or live endpoint data.
