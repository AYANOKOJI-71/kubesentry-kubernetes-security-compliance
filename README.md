# KubeSentry — Kubernetes Security & Compliance Scanner

KubeSentry is a **defensive local-manifest review** workspace for Kubernetes YAML that an operator owns or is explicitly authorized to assess. It inventories supplied resources, evaluates a versioned reviewed-baseline policy set, and returns evidence-rich findings with remediation context. The project is designed for demonstration and controlled client-review workflows; it does not discover clusters, execute manifests, retain credentials, or probe remote targets.

> KubeSentry is advisory software, not an authorization mechanism or a substitute for a platform team’s change-management process. Assess only manifests you are authorized to review.

## What the demonstration proves

| Capability | Implementation evidence |
|---|---|
| Policy-as-code architecture | A Python evaluator produces deterministic reports today, while illustrative Rego policies preserve an explicit OPA integration boundary for a future authorized platform adapter. |
| Explainable compliance review | Every finding contains severity, policy ID, resource identity, evidence path, rationale, and remediation guidance. |
| Controlled security posture | The API accepts supplied YAML and bundled synthetic fixtures only. It offers no cluster-discovery, remote-target, command-execution, or mutation endpoint. |
| Analyst experience | The React console compares an insecure synthetic workload, a hardened reviewed baseline, and an operator-supplied local YAML workflow. |
| Operational readiness | The project includes focused backend and frontend tests, an API container, a Compose workflow, a metrics endpoint, and GitHub Actions quality gates. |

The reviewed checks cover workload privilege boundaries, run-as settings, Linux capabilities, seccomp, resource controls, image pinning, service-account-token mounting, and bundled network-isolation evidence. These controls are aligned with the intent of Kubernetes’ Pod Security Standards, which identify privileged containers, privilege escalation, capabilities, host namespaces, and seccomp as key workload hardening concerns.[1]

## Safe local workflow

```text
Synthetic fixture or explicitly supplied YAML
               ↓
FastAPI input validation → manifest parser → reviewed-baseline policy engine
               ↓
Evidence-rich scan report → React analyst console / Prometheus-style counters
```

| Command | Purpose |
|---|---|
| `make setup` | Creates a Python virtual environment, installs backend dependencies, and installs the React workspace. |
| `make api` | Starts the local API at `http://localhost:4900`. |
| `make web` | Starts the analyst console at `http://localhost:5200`. |
| `make test` | Runs Ruff, backend tests, and frontend API-contract tests. |
| `make build` | Type-checks and builds the production React bundle. |
| `make docker-api` | Builds and starts only the local review API with Docker Compose. |

Run `make api` and `make web` in separate terminals, then open `http://localhost:5200`. Select either synthetic fixture, or use **Review YAML** to assess an authorized local manifest bundle. The console intentionally communicates that no cluster discovery, execution, or modification occurs.

## Policy profile and documents

The `reviewed-baseline / v0.1` profile evaluates 11 controls. Review [`docs/POLICY_CATALOG.md`](docs/POLICY_CATALOG.md) for the policy identifiers, evidence model, remediation language, and known limitations. The technical boundaries are documented in [`docs/SAFE_USE.md`](docs/SAFE_USE.md), and the implementation flow appears in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

| File | Purpose |
|---|---|
| `fixtures/insecure/demo.yaml` | Synthetic high-risk workload for deterministic evidence review. |
| `fixtures/secure/demo.yaml` | Synthetic hardened baseline with the full profile satisfied. |
| `apps/api/src/kubesentry/engine.py` | Deterministic Python policy evaluation and finding construction. |
| `policies/*.rego` | Illustrative policy-as-code references for a future authorized OPA adapter. |
| `docs/DEMO-VERIFICATION.md` | Recorded local console and API workflow verification. |

## Boundaries and limitations

KubeSentry evaluates the YAML text that an operator supplies; it does not prove that a target cluster applies the desired admission configuration, CNI enforcement, RBAC, image provenance, or runtime controls. For real client work, pair the output with scope authorization, a reviewed change process, environment-specific evidence, and human validation. The project deliberately avoids high-risk automation and uses synthetic data in its bundled demonstration.

## References

[1] [Kubernetes Documentation — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
