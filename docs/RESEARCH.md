# Research basis and contribution boundaries

Reviewed 28 October 2026. These are primary project/specification/security sources. This is an engineering synthesis and bounded experiment platform; it does not claim the underlying algorithms are new or a patentable first.

| Source | Design use | Boundary |
|---|---|---|
| [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) | Directional isolation, additive allows, namespace peers, enforcement and NAT limitations. | Permission is not application correctness or universal runtime truth. |
| [NetworkPolicy API](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/) | Field/default/port/peer semantics and strict input checks. | Vendor/AdminNetworkPolicy and unresolved IP/host cases remain Unknown. |
| [NP-Guard netpol-analyzer](https://github.com/np-guard/netpol-analyzer) | Established evaluate/list/explain/diff capability informed the baseline. | No claim that semantic diff or explanations are novel. An independent differential run against NP-Guard is not included in release validation. |
| [NP-Guard Network Config Analyzer](https://github.com/np-guard/network-config-analyzer) / [pinned PyPI release](https://pypi.org/project/network-config-analyzer/2.1.0/) | Optional independently implemented oracle; 28 fixtures and 5,472 decisions compared. | One cross-namespace `DoesNotExist` disagreement is retained and reduced, not suppressed. See `ORACLE_CHECK.md`. This is a different tool from the Go netpol-analyzer above. |
| [Cyclonus](https://github.com/mattfenwick/cyclonus) | Truth-table/conformance testing and probing are prior work. | The shipped release has its own tests; no Cyclonus conformance certification is claimed. |
| [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Agent/tool isolation, least privilege, explicit assumptions, and abuse-case testing motivated the containment scenario. | No prompt-injection detector, autonomous exploit, CVE scanner, or credential/RBAC attack graph is implemented. |
| [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) | Dedicated limited lab identity and disabled service-account token mounting in fixtures. | Dynamic namespace lifecycle permissions remain broad within a dedicated disposable cluster. |
| [kind releases](https://github.com/kubernetes-sigs/kind/releases) and [Calico kind installation](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind) / [requirements](https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements) | Digest-pinned node, explicit CNI installation, version support, and isolated local lab. | Setup files are based on the documented approach; real integration was unavailable in this environment. |
| [kubectl delete implementation](https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/delete/delete.go) | Raw DELETE with a supplied DeleteOptions body enables a UID precondition. | Scripted-adapter tests do not replace a real API-server test. |
| [FastAPI testing](https://fastapi.tiangolo.com/tutorial/testing/) | HTTP application checks and shared service boundary. | The product is local/single-reviewer, not a hosted multi-tenant application. |
| [Zeller & Hildebrandt, 2002](https://doi.org/10.1109/32.988498) | Failure-preserving input reduction inspired paired-policy deletion. | The reducer is a domain adaptation of an established idea, with 1-minimal/budget-limited labels. |

## What makes the release distinctive

1. **Containment beyond direct intents.** A deliberately small agent/tool scenario demonstrates how direct checks can pass while a new conditional relay path reaches an asset. Each hop links to policy evidence. Single-pivot sensitivity searches all scoped routes again; the parallel-relay scenario demonstrates an alternate route surviving removal of the first assumption. These changes do not change policy permissions.
2. **Counterfactuals with constraints.** Repair proposals are small baseline reverts checked against every declared tuple/intent and the conditional baseline asset-pair set. They expose newly reachable paths instead of declaring universal safety.
3. **Portable failing cases.** A reduction bundle keeps a particular connection's decisions, isolation conditions, and relevant intent violations, with a static replay verifier and a separate real-cluster path.
4. **Intent-suite sensitivity.** Controlled mistakes reveal which changed behaviours the declared intents fail to catch. Equivalent-on-scope edits are separated from effective ones; sensitivity is not reported as analyzer accuracy.

The measured contribution is therefore a reproducible workflow from policy change to consequence, constrained counterfactual, and small reproduction. A larger independent benchmark and real CNI replay study would be the next research step, not an already achieved result.
