"""Small deterministic property-style checks for security parsers."""
import pytest

from isolatevm.cpu import CPUSelectionError, format_cpu_set, parse_cpu_set
from isolatevm.model import EgressRule, ValidationError, _copy_guest_path


@pytest.mark.parametrize("selection", [
    "0", "0-0", "0-2,4", "6,0-2", "3-5,0-1", "0,2,4,6",
])
def test_cpu_set_normalization_is_idempotent(selection):
    canonical = format_cpu_set(parse_cpu_set(selection))
    assert format_cpu_set(parse_cpu_set(canonical)) == canonical
    assert len(parse_cpu_set(canonical)) == len(parse_cpu_set(selection))


@pytest.mark.parametrize(("kind", "value", "normalized"), [
    ("domain", "Api.GitHub.COM.", "api.github.com"),
    ("ip", "192.0.2.1", "192.0.2.1"),
    ("cidr", "192.0.2.0/24", "192.0.2.0/24"),
])
def test_egress_rule_parse_normalization_is_idempotent(kind, value, normalized):
    rule = EgressRule.parse({"kind": kind, "value": value, "port": 443})
    assert rule.value == normalized
    assert EgressRule.parse({"kind": rule.kind, "value": rule.value,
                             "port": rule.port}) == rule


@pytest.mark.parametrize("raw", [
    None, [], {"kind": "domain", "value": "example.com; accept", "port": 443},
    {"kind": "domain", "value": "example.com\nacl injected", "port": 443},
    {"kind": "ip", "value": "127.0.0.1; accept", "port": 443},
    {"kind": "cidr", "value": "10.0.0.0/8\naccept", "port": 443},
    {"kind": "ip", "value": "127.0.0.1", "port": True},
])
def test_egress_parser_rejects_malformed_or_syntax_injection_values(raw):
    with pytest.raises(ValidationError):
        EgressRule.parse(raw)


@pytest.mark.parametrize("path", [
    "/home/ubuntu/project", "/home/ubuntu/imports/tool/src",
    "/home/ubuntu/build/cache/output",
])
def test_guest_copy_path_validation_is_idempotent(path):
    assert _copy_guest_path(_copy_guest_path(path)) == path


@pytest.mark.parametrize("path", [
    "/home/ubuntu/../etc/passwd", "/home/ubuntu//work", "/home/ubuntu/./work",
    "/home/ubuntu/work\nother", "/home/other/work", "relative/path",
])
def test_guest_copy_path_parser_rejects_ambiguous_paths(path):
    with pytest.raises(ValidationError):
        _copy_guest_path(path)


@pytest.mark.parametrize("selection", [
    "", "0,0", "4-2", "00", "0-999", "1, 2", "1;2", "1\n2",
])
def test_cpu_set_parser_rejects_ambiguous_or_unbounded_inputs(selection):
    with pytest.raises(CPUSelectionError):
        parse_cpu_set(selection)
