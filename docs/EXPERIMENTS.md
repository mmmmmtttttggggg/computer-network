# What the final additions demonstrate

## Find checks that the current suite is missing

Load **A clean baseline**, click **Run review**, open **Experiments**, and click **Suggest missing checks**. On the included fixture the bounded generator creates 24 unique edits, 20 of which change known decisions. Four draft assertions raise detection from **8/14 to 14/14 training faults**, and from **2/6 to 4/6 held-out faults**. Two held-out faults still escape. Download the checks and verify them on the reference.

The selector uses only training faults. It greedily chooses exact tuples that catch missed edits; the holdout measures transfer after selection. These are faults from the same synthetic generator, not independent real-world vulnerabilities. The expectations preserve the reference candidate, which must first have known decisions and passing candidate intents. A human must decide whether that reference expresses the desired security requirements. Time-limited results explicitly identify a partial suite.

This gives a concrete evaluation question: **does a suggested check suite catch mistakes the existing intent suite misses, including held-out edits?** It is a defensible project contribution without claiming a new general-purpose analysis algorithm.

## Labels are part of the security boundary

Load **The indirect escape**. In Experiments, choose `apps/agent`, click **Set app=payments (demo)**, then **Analyze label counterfactual**. The agent no longer matches its egress isolation policy and now matches the database's trusted peer selector. Twenty permissions change. The existing two-hop asset path becomes a direct one; this is shown separately from a newly reachable asset pair. Agent-specific intents lose their matches and remain INVALID.

The result is a new configuration hypothesis, not proof of an RBAC exploit or an attacker's right to change labels. The original saved review stays unchanged. **Open edited scenario as new review** makes the full result inspectable and exportable. For a second example, run the same label edit against **A clean baseline**: the database asset pair is newly exposed.

## Ask another question without hiding scope

In **Connections**, expand **Ask about another connection**. Try `apps/agent` → `data/database`, TCP/12345, expected Deny. It returns PASS for that exact candidate check. Save it as JSON and run it on later project revisions with `netscope check`. This does not silently add queries to the saved report or claim runtime coverage for the new port.

## Two small cases that are easy to explain

- **The last policy disappears:** deleting the final selecting policy removes isolation, so deletion can open access. All five existing intents still pass. This shows why textual diffs and green intent tests alone are insufficient.
- **The cross-namespace check:** two Pods, one policy, and one exact TCP assertion reproduce a known independent-analyzer disagreement. The included live plan lets the actual CNI provide additional evidence. No CNI outcome is prefilled or assumed.

Kubernetes' documented policy union/isolation and combined-peer semantics underpin these cases: [NetworkPolicy concepts](https://kubernetes.io/docs/concepts/services-networking/network-policies/), [API reference](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/), and [label selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/). The interpretation and experimental methods are NetScope's bounded implementation; these references do not establish novelty or universal correctness.
