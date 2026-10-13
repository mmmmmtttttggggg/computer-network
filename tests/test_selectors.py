import pytest

from app.model.selectors import LabelSelector, SelectorError, matches, parse_selector
from app.model.topology import Namespace, Pod


def expr(key, op, values=None):
    e = {"key": key, "operator": op}
    if values is not None:
        e["values"] = values
    return {"matchExpressions": [e]}


# --- matchLabels ---------------------------------------------------------
def test_exact_label_match():
    assert matches({"matchLabels": {"app": "payments"}}, {"app": "payments", "tier": "be"})


def test_incorrect_label_value():
    assert not matches({"matchLabels": {"app": "payments"}}, {"app": "analytics"})


def test_missing_label_key_fails_match_labels():
    assert not matches({"matchLabels": {"app": "payments"}}, {"tier": "be"})


def test_multiple_conditions_all_must_match():
    sel = {
        "matchLabels": {"app": "payments"},
        "matchExpressions": [
            {"key": "env", "operator": "In", "values": ["prod", "stage"]},
            {"key": "debug", "operator": "DoesNotExist"},
        ],
    }
    assert matches(sel, {"app": "payments", "env": "prod"})
    assert not matches(sel, {"app": "payments", "env": "dev"})
    assert not matches(sel, {"app": "payments", "env": "prod", "debug": "1"})
    assert not matches(sel, {"app": "other", "env": "prod"})


# --- In / NotIn ----------------------------------------------------------
@pytest.mark.parametrize("labels,expected", [
    ({"env": "prod"}, True),
    ({"env": "stage"}, True),
    ({"env": "dev"}, False),
    ({}, False),  # missing key never matches In
])
def test_in(labels, expected):
    assert matches(expr("env", "In", ["prod", "stage"]), labels) is expected


@pytest.mark.parametrize("labels,expected", [
    ({"env": "dev"}, True),
    ({"env": "prod"}, False),
    ({}, True),  # missing key matches NotIn
    ({"other": "x"}, True),
])
def test_not_in(labels, expected):
    assert matches(expr("env", "NotIn", ["prod", "stage"]), labels) is expected


# --- Exists / DoesNotExist ----------------------------------------------
def test_exists():
    assert matches(expr("app", "Exists"), {"app": "x"})
    assert matches(expr("app", "Exists"), {"app": ""})  # empty value still exists
    assert not matches(expr("app", "Exists"), {"tier": "x"})
    assert not matches(expr("app", "Exists"), {})


def test_does_not_exist():
    assert matches(expr("app", "DoesNotExist"), {"tier": "x"})
    assert matches(expr("app", "DoesNotExist"), {})
    assert not matches(expr("app", "DoesNotExist"), {"app": "x"})
    assert not matches(expr("app", "DoesNotExist"), {"app": ""})


# --- Empty selectors -----------------------------------------------------
@pytest.mark.parametrize("sel", [{}, {"matchLabels": {}}, {"matchExpressions": []}])
def test_empty_selector_matches_everything(sel):
    assert matches(sel, {})
    assert matches(sel, {"app": "x", "tier": "y"})


def test_parsed_selector_object_accepted():
    parsed = parse_selector({"matchLabels": {"app": "x"}})
    assert isinstance(parsed, LabelSelector)
    assert matches(parsed, {"app": "x"})


# --- Malformed selectors -------------------------------------------------
@pytest.mark.parametrize("bad", [
    None,
    "app=payments",
    ["app"],
    {"matchlabels": {"app": "x"}},                 # wrong case / unknown field
    {"matchLabels": ["app"]},
    {"matchLabels": {"app": 5}},                   # non-string value
    {"matchLabels": {"": "x"}},                    # empty key
    {"matchExpressions": {"key": "a"}},            # not a list
    {"matchExpressions": ["a"]},                   # entry not a mapping
    {"matchExpressions": [{"operator": "Exists"}]},            # missing key
    {"matchExpressions": [{"key": "a"}]},                      # missing operator
    {"matchExpressions": [{"key": "a", "operator": "Exists", "extra": 1}]},
    {"matchExpressions": [{"key": "", "operator": "Exists"}]},
    {"matchExpressions": [{"key": "a", "operator": "Equals", "values": ["x"]}]},
    {"matchExpressions": [{"key": "a", "operator": "in", "values": ["x"]}]},  # case-sensitive
    {"matchExpressions": [{"key": "a", "operator": "In"}]},                   # no values
    {"matchExpressions": [{"key": "a", "operator": "In", "values": []}]},
    {"matchExpressions": [{"key": "a", "operator": "NotIn", "values": "x"}]},
    {"matchExpressions": [{"key": "a", "operator": "In", "values": [1]}]},
    {"matchExpressions": [{"key": "a", "operator": "Exists", "values": ["x"]}]},
    {"matchExpressions": [{"key": "a", "operator": "DoesNotExist", "values": ["x"]}]},
])
def test_malformed_selector_raises(bad):
    with pytest.raises(SelectorError):
        parse_selector(bad)
    with pytest.raises(SelectorError):
        matches(bad, {"app": "x"})


def test_selector_error_is_value_error():
    assert issubclass(SelectorError, ValueError)


# --- Integration with topology objects -----------------------------------
def test_matches_topology_labels():
    ns = Namespace("prod", {"team": "pay"})
    pod = Pod("payments-0", "prod", {"app": "payments"})
    assert matches({"matchLabels": {"team": "pay"}}, ns.labels)
    assert matches({"matchLabels": {"app": "payments"}}, pod.labels)
    assert not matches({"matchLabels": {"app": "payments"}}, ns.labels)