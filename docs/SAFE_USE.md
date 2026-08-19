# Authorized Use and Safety Controls

KubeSentry is intended for the review of Kubernetes manifests that the operator owns or is explicitly authorized to assess. It accepts local manifest text and fixture names only. It does not probe cluster endpoints, enumerate remote resources, test identity boundaries, deploy workloads, modify Kubernetes objects, or make outbound requests.

The bundled `insecure` fixture is a deliberately synthetic teaching example. It contains no credentials, production hosts, personal data, client data, or real cluster identifiers. Use it only to validate the user interface and policy findings.

## Operating rules

| Requirement | KubeSentry behavior |
|---|---|
| Explicit authorization | The operator supplies the manifest bundle or chooses a local fixture. |
| Scope control | No cluster discovery or remote target entry points are present. |
| Least data | Reports store resource metadata and evidence paths, not raw credentials. |
| Non-destructive review | Findings are advisory; no change is applied to any manifest or cluster. |
| Human accountability | A qualified operator reviews policy context and remediation before enforcement. |

For production use, introduce a documented approval workflow, least-privilege read-only service accounts, retention controls, environment-specific policy exceptions, and independent validation before enabling any connector.
