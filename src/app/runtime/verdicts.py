"""Conservative runtime interpretation, independent of the cluster adapter."""


def classify_observation(model, attempts, *, controls_healthy, drift=False):
    outcomes = [a.get("outcome") for a in attempts]
    if (
        model not in ["Allow", "Deny"]
        or drift
        or not controls_healthy
        or len(outcomes) != 3
        or "error" in outcomes
    ):
        return {"verdict": "INCONCLUSIVE", "mismatch": False, "complete": False}
    successes = outcomes.count("success")
    if model == "Deny" and successes:
        return {"verdict": "UNEXPECTED_REACHABILITY", "mismatch": True, "complete": True}
    if successes == 3:
        return {"verdict": "OBSERVED_AGREEMENT", "mismatch": False, "complete": True}
    if successes == 0 and all(o == "unreachable" for o in outcomes):
        return {"verdict": "OBSERVED_UNREACHABLE", "mismatch": model == "Allow", "complete": True}
    return {"verdict": "INCONCLUSIVE", "mismatch": False, "complete": False}
