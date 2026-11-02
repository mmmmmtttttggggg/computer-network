"""The adapter must reject output it cannot interpret, including partial parses."""

import runpy
from pathlib import Path
import pytest

harness = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "oracle_check.py"))
matches = harness["connection_matches"]


@pytest.mark.parametrize(
    "text,protocol,port,expected",
    [
        ("All connections", "UDP", 5353, True),
        ("No connections", "TCP", 8080, False),
        ("{protocols:TCP,dst_ports:8080-8081}", "TCP", 8080, True),
        ("{protocols:TCP,dst_ports:8080-8081}", "TCP", 8082, False),
        ("{protocols:TCP,dst_ports:8080-8081}", "UDP", 8080, False),
        ("{protocols:TCP,dst_ports:8080,8082},{protocols:UDP,dst_ports:5353}", "UDP", 5353, True),
        ("{protocols:TCP,UDP}", "UDP", 9000, True),
        ("{dst_ports:8080}", "TCP", 8080, True),
    ],
)
def test_pinned_oracle_output_membership(text, protocol, port, expected):
    assert matches(text, protocol, port) is expected


@pytest.mark.parametrize(
    "text",
    [
        "{protocols:TCP,dst_ports:8080} ignored",
        "{src_ports:1234}",
        "{protocols:unknown}",
        "{dst_ports:8081-8080}",
        "",
        "{}",
    ],
)
def test_unknown_oracle_notation_is_an_error(text):
    with pytest.raises(ValueError):
        matches(text, "TCP", 8080)


def test_oracle_separate_protocol_lines_are_both_retained():
    parsed = harness["oracle_map"](
        "apps/a => data/b : {protocols:TCP,dst_ports:8080}\n"
        "apps/a => data/b : {protocols:UDP,dst_ports:5353}\n",
        {"apps/a", "data/b"},
    )
    assert len(parsed[("apps/a", "data/b")]) == 2
    assert any(matches(text, "UDP", 5353) for text in parsed[("apps/a", "data/b")])
