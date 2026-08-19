# KubeSentry Policy Catalogue

The included policy profile is a focused review baseline for **operator-supplied manifests**. A finding is advisory evidence for an authorized reviewer; it is not an exploitation attempt, a cluster scan, or a substitute for validating an environment-specific security design.

| ID | Check | Severity | Evidence | Remediation summary |
|---|---|---:|---|---|
| `KSB-001` | Privileged container | Critical | `securityContext.privileged` is `true`. | Remove privileged mode and use narrowly scoped capabilities only when justified. |
| `KSB-002` | Privilege escalation allowed | High | `allowPrivilegeEscalation` is not explicitly `false`. | Set it to `false` at each container security context. |
| `KSB-003` | Root execution possible | High | `runAsNonRoot` is absent/false, or `runAsUser` is `0`. | Require non-root execution and configure a non-zero user where appropriate. |
| `KSB-004` | Seccomp profile missing | Medium | No effective `RuntimeDefault` or `Localhost` seccomp profile. | Configure a pod-level or container-level seccomp profile. |
| `KSB-005` | Capabilities not dropped | Medium | A container does not drop `ALL` capabilities. | Drop `ALL`; add only the narrowly required capability. |
| `KSB-006` | Host namespace sharing | High | `hostNetwork`, `hostPID`, or `hostIPC` is enabled. | Disable host namespace sharing unless it is a justified infrastructure workload. |
| `KSB-007` | HostPath volume | High | A Pod template mounts a `hostPath` volume. | Prefer CSI, projected, config, secret, or persistent volumes. |
| `KSB-008` | Unpinned or latest image | Medium | Image has no tag, uses `latest`, or lacks an immutable digest. | Use an approved version tag and consider a digest for release immutability. |
| `KSB-009` | Resource controls missing | Low | Container requests or limits are absent. | Define CPU and memory requests and limits for schedulability and containment. |
| `KSB-010` | Default service-account token | Medium | Pod template does not set `automountServiceAccountToken: false`. | Disable automatic token mounting unless the workload needs Kubernetes API access. |
| `KSB-011` | Network-isolation evidence missing | Medium | A workload namespace has no NetworkPolicy resource in the evaluated bundle. | Add reviewed ingress and egress policies; verify the CNI enforces them. |

`KSB-011` is intentionally phrased as missing evidence rather than a definitive exposure: Kubernetes NetworkPolicy enforcement is dependent on the cluster’s network plugin, and a complete policy might live outside the submitted bundle. [1]

## Profiles and limitations

The **reviewed-baseline** profile runs all checks above. Policy decisions must be tailored for system namespaces, admission controllers, and other trusted infrastructure workloads. KubeSentry does not infer production context, evaluate admission hooks, verify image signatures, query vulnerability databases, or prove runtime behavior.

[1]: https://kubernetes.io/docs/concepts/services-networking/network-policies/ "Kubernetes Network Policies"
