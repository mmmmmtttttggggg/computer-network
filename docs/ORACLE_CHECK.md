# Independent analyzer check

The retained release 1.1 baseline was compared with the separately implemented **Network Config Analyzer (NCA) 2.1.0**. NCA is an NP-Guard project, distinct from the Go `netpol-analyzer`. It is an optional development oracle, never a runtime dependency or an unquestioned source of truth.

## Recorded result

| Measure | Result |
|---|---:|
| Fixtures | 28 |
| Shipped fixtures / seeded generated fixtures | 4 / 24 |
| Decisions compared across both revisions | 5,472 |
| Matching decisions | 5,471 |
| Disagreements retained | 1 |

Seed **303** is fixed. Generated fixtures use four Pods in two namespaces, directional isolation, additive policies/rules, combined/separate peers, selector expressions, numeric/named destination ports, and inclusive ranges. The four shipped fixtures are agent escape, checkout, selector trap, and clean baseline. This is a bounded engineering check, not a representative cluster study or a correctness percentage for unseen inputs.

The adapter reads NCA's ungrouped Pod-pair connectivity output. Multiple protocol lines are unioned. Unknown output notation or failed oracle execution stops the check; it is never silently interpreted as Deny. Oracle output is generated in a fresh temporary file because NCA appends to existing files. The adapter has its own tests.

Raw projects, manifests, oracle outputs/logs, input hashes, per-case totals, and the complete disagreement are retained in `artifacts/oracle/`. `environment.txt` records the separate oracle installation.

## The retained disagreement

Original location: case 08, candidate, `data/b → apps/b TCP/8080`. NetScope reports **Allow**; NCA 2.1.0 reports **Deny**.

Deletion reduced the case from eight policies/four Pods to one policy/two Pods. Its egress peer combines `namespaceSelector: {}` with a Pod selector whose `absent` key uses `DoesNotExist`. Neither Pod has that key. Destination ingress is unisolated. NetScope's interpretation allows the cross-namespace destination; NCA 2.1.0 excludes it in this case.

| Reduced control | NetScope | NCA 2.1.0 |
|---|---|---|
| Cross-namespace `DoesNotExist` peer | Allow | Deny |
| Replace its Pod selector with `{}` | Allow | Allow |
| Add the key only to the source Pod | Allow | Deny |
| Add the key to the destination Pod | Deny | Deny |

The [Kubernetes label-selector documentation](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) defines absence selection, and the [NetworkPolicy documentation](https://kubernetes.io/docs/concepts/services-networking/network-policies/) describes combining namespace and Pod selectors within a peer. Code inspection of the installed NCA parser suggests it restricts this Pod-expression selection to the policy namespace. This is an interpretation supported by the reduced controls; it is **not a real-CNI adjudication or a confirmed upstream issue**. No external bug report was submitted.

The reduced project, manifest, raw oracle result, and controls are in `artifacts/oracle/disagreement/`. It deliberately has no application intents; its overall review gate is therefore incomplete. Inspect the explicit query decision when replaying it. The engine is not changed merely to make two tools agree.

## Reproduce

Keep NCA separate because it pins different dependencies:

```bash
python3 -m venv .oracle-venv
.oracle-venv/bin/python -m pip install network-config-analyzer==2.1.0
.venv/bin/python scripts/oracle_check.py --nca .oracle-venv/bin/nca
```

On Windows use `Scripts/python.exe` and `Scripts/nca.exe`. The command exits **1 when disagreements exist**; that is the expected result for this retained seed. Exit 0 means agreement on the compared scope only. Oracle/parser errors raise an error instead of creating a successful summary.

Replay just the reduced case into a separate evidence directory:

```bash
.venv/bin/python scripts/oracle_check.py --nca .oracle-venv/bin/nca \
  --project artifacts/oracle/disagreement/minimal-project.json \
  --output artifacts/oracle-replay
```

These checks exclude external IP/NAT, host-network, vendor/AdminNetworkPolicy, and enforcement behaviour. Real-cluster verification remains a separate gate.

## Release 1.2 live-ready case

`src/app/resources/examples/cross-namespace-check.json` keeps the reduced two-Pod/one-policy structure and exact TCP query, while adding a `must_allow` application intent based on the specification interpretation. This makes its initial live plan executable without changing the historical reproducer. It is a declared hypothesis to test, not independent proof. Use the dashboard scenario and `docs/FINALIZATION.md` to collect actual CNI observations. The historical NCA artifacts remain unmodified and labeled 1.1.
