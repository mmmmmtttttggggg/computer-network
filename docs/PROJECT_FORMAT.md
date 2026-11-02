# Project input format

Use one JSON/YAML project object. The eight files in `src/app/resources/examples/` are complete working examples. Resource fields can be lists of Kubernetes objects or quoted multi-document YAML strings. Kubernetes `List.items` is also accepted for a resource field.

| Field | Meaning |
|---|---|
| `schemaVersion` | Integer 1. |
| `name`, `description` | Presentation text, up to 200/4,000 characters. |
| `topology` | Explicit `v1/Namespace`, `v1/Pod`, or `apps/v1/Deployment` resources. Namespaces must exist in this input; none is inferred. Deployment templates represent one logical endpoint. |
| `baseline`, `candidate` | Standard NetworkPolicy resources. Other influencing policy kinds produce Unknown; Kubernetes Secret objects are rejected. |
| `intents` | List of the intent format below. Empty intent suites do not receive a complete pass. |
| `queries` | Optional explicit tuples. If absent, all distinct endpoint pairs are evaluated for declared container-port, intent-port, and extra `ports` combinations. Matching intent tuples are added in either case. |
| `ports` | Optional extra protocol/port combinations for generated all-pairs scope. |
| `approvals` | Exact report `tuple_id`, `baseline`, `candidate`. Clears only that semantic-change gate. |
| `threatModel` | Optional `entrypoints`, `pivots`, `assets` arrays of namespace/Pod IDs, plus description. Each array requires unique valid IDs. |

Intent example:

```yaml
id: payments-to-database
source:
  namespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: apps}
  podSelector:
    matchLabels: {app: payments}
destination:
  namespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: data}
  podSelector:
    matchLabels: {app: database}
protocol: TCP
port: 5432
expect: must_allow  # or must_deny
```

Unlike a NetworkPolicy peer's omitted namespace selector, an intent endpoint's omitted namespace selector intentionally means all namespaces. This is a separate application assertion language. Self-pairs are excluded from intent expansion; explicitly queried self traffic is Unknown.

Explicit tuple examples:

```yaml
queries:
  - source: apps/payments
    destination: data/database
    protocol: TCP
    port: 5432
  - source: apps/agent
    destination: external:192.0.2.10
    protocol: TCP
    port: 443
```

An external-IP tuple evaluates only the Pod-controlled direction. CIDR `except` exclusions are applied. Named destination ports on an external endpoint are unresolved; Pod/IP-block NAT behaviour is deliberately not guessed. External queries remain outside the initial live and conditional-containment subsets.

A threat model example:

```yaml
threatModel:
  entrypoints: [apps/agent]
  pivots: [apps/tool-gateway]
  assets: [data/database]
  description: Assume a compromised agent and a gateway capable of relaying requests.
```

This declares the pivot assumption; an allowed incoming edge does not automatically compromise its destination. Assets are not inferred from images or names. The view never claims to prove an application vulnerability.

The ingestion boundary rejects duplicate YAML keys, YAML aliases/unsafe tags, duplicate object IDs, invalid schemas/ports/selectors, missing namespaces, contradictory intents, and malformed references. Contradictory or zero-match intents are represented as invalid review outcomes. Nested structures and input sizes are bounded.

Before persistence, workload specs are reduced to model-relevant identity/labels/ports/origin/service-account fields. Application images are replaced with a non-executable placeholder; commands, environment values, mounts, status, and irrelevant annotations are not retained. Policy annotations are dropped. Hashes bind the normalized snapshot, not original file bytes. Required labels and policy fields remain visible in evidence.

## Portable connection checks (release 1.2)

Checks are a separate JSON format consumed by `netscope check project.json checks.json`:

```json
{"schemaVersion":1,"checks":[{"id":"agent-no-db","source":"apps/agent","destination":"data/database","protocol":"TCP","port":5432,"expect":"must_deny"}]}
```

Supply 1–32 unique IDs and connection tuples. Endpoints must exist in the project (or use the explicit `external:IP` form), protocol is TCP/UDP/SCTP, and port is an integer 1–65535. Conflicting/duplicate tuples are rejected. `expect` is `must_allow` or `must_deny`. Unknown cannot pass. A check may use a port absent from the saved review's grid. It is evaluated separately and does not expand that review or its live plan.

Generated files optionally include `reference_input_hash`. It identifies the reviewed reference, not a restriction preventing execution on future candidates. Results report whether the current normalized input has that same hash. The full review's approvals/intents remain independent of these exact connection assertions.
