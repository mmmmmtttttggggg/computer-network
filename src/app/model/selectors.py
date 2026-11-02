"""Kubernetes-style label selector parsing and matching (no external dependencies).

Validation behaviour:
  * `parse_selector(None)` and any non-mapping input raise SelectorError.
  * `{}` is a valid *empty* selector and matches every label set.
  * Unknown top-level keys, unknown operators (case-sensitive), non-string
    labels/values, empty keys, and wrong `values` shapes raise SelectorError.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Tuple, Union


class SelectorError(ValueError):
    """Raised for malformed selector definitions."""


IN, NOT_IN, EXISTS, DOES_NOT_EXIST = "In", "NotIn", "Exists", "DoesNotExist"
_SET_OPS = (IN, NOT_IN)
_PRESENCE_OPS = (EXISTS, DOES_NOT_EXIST)
VALID_OPERATORS = _SET_OPS + _PRESENCE_OPS


@dataclass(frozen=True)
class Requirement:
    key: str
    operator: str
    values: Tuple[str, ...] = ()


@dataclass(frozen=True)
class LabelSelector:
    match_labels: Tuple[Tuple[str, str], ...] = ()
    match_expressions: Tuple[Requirement, ...] = ()


def _require_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise SelectorError(f"{what} must be a string, got {value!r}")
    return value


def _parse_requirement(raw: Any) -> Requirement:
    if not isinstance(raw, Mapping):
        raise SelectorError(f"matchExpressions entry must be a mapping, got {raw!r}")
    unknown = set(raw) - {"key", "operator", "values"}
    if unknown:
        raise SelectorError(f"unknown fields in matchExpressions entry: {sorted(map(str, unknown))}")
    if "key" not in raw or "operator" not in raw:
        raise SelectorError("matchExpressions entry requires 'key' and 'operator'")
    key = _require_str(raw["key"], "expression key")
    if not key:
        raise SelectorError("expression key must be non-empty")
    op = raw["operator"]
    if op not in VALID_OPERATORS:
        raise SelectorError(f"invalid operator {op!r}; expected one of {list(VALID_OPERATORS)}")

    raw_values = raw.get("values")
    if op in _SET_OPS:
        if not isinstance(raw_values, (list, tuple)) or not raw_values:
            raise SelectorError(f"operator {op} requires a non-empty 'values' list")
        values = tuple(_require_str(v, "expression value") for v in raw_values)
    else:
        if raw_values not in (None, [], ()):
            raise SelectorError(f"operator {op} must not have 'values'")
        values = ()
    return Requirement(key, op, values)


def parse_selector(data: Any) -> LabelSelector:
    """Validate a selector dict (as parsed from YAML/JSON) into a LabelSelector."""
    if not isinstance(data, Mapping):
        raise SelectorError(f"selector must be a mapping, got {data!r}")
    unknown = set(data) - {"matchLabels", "matchExpressions"}
    if unknown:
        raise SelectorError(f"unknown selector fields: {sorted(map(str, unknown))}")

    labels = data.get("matchLabels", {})
    if labels is None:
        labels = {}
    if not isinstance(labels, Mapping):
        raise SelectorError("matchLabels must be a mapping")
    pairs = []
    for k, v in labels.items():
        k = _require_str(k, "matchLabels key")
        if not k:
            raise SelectorError("matchLabels key must be non-empty")
        pairs.append((k, _require_str(v, f"matchLabels value for {k!r}")))

    exprs = data.get("matchExpressions", [])
    if exprs is None:
        exprs = []
    if not isinstance(exprs, (list, tuple)):
        raise SelectorError("matchExpressions must be a list")
    return LabelSelector(tuple(pairs), tuple(_parse_requirement(e) for e in exprs))


def _requirement_matches(req: Requirement, labels: Mapping[str, str]) -> bool:
    present = req.key in labels
    if req.operator == IN:
        return present and labels[req.key] in req.values
    if req.operator == NOT_IN:
        return (not present) or labels[req.key] not in req.values
    if req.operator == EXISTS:
        return present
    return not present  # DoesNotExist


def matches(selector: Union[LabelSelector, Mapping[str, Any]], labels: Mapping[str, str]) -> bool:
    """True if all conditions match `labels`. Empty selector matches everything.

    A raw dict is validated first, so malformed input raises SelectorError.
    """
    if not isinstance(selector, LabelSelector):
        selector = parse_selector(selector)
    for k, v in selector.match_labels:
        if k not in labels or labels[k] != v:
            return False
    return all(_requirement_matches(r, labels) for r in selector.match_expressions)
