from datetime import datetime, timedelta, timezone

import pytest

from isolatevm.incus import IncusError, LocalIncus
from isolatevm.metrics import cpu_percent_between, parse_state


def test_state_counters_and_uptime_are_typed():
    started = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    result = parse_state({"status": "Running", "started_at": started,
        "cpu": {"usage": 5_000_000_000}, "memory": {"usage": 1024, "total": 4096},
        "disk": {"root": {"usage": 2_000, "total": 8_000}},
        "network": {"eth0": {"counters": {"bytes_received": 300, "bytes_sent": 500}},
                    "lo": {"counters": {"bytes_received": 100, "bytes_sent": 200}}}})
    assert result.cpu_ns == 5_000_000_000
    assert result.memory_bytes == 1024 and result.disk_total_bytes == 8_000
    assert result.network_rx_bytes == 400 and result.network_tx_bytes == 700
    assert 590 <= result.uptime_seconds <= 610


def test_missing_counters_stay_unavailable():
    result = parse_state({"status": "Stopped", "started_at": "0001-01-01T00:00:00Z"})
    assert result.cpu_ns is None and result.memory_bytes is None
    assert result.network_rx_bytes is None and result.uptime_seconds is None
    with pytest.raises(ValueError): parse_state({"cpu": []})


def test_cpu_usage_needs_two_valid_counters_and_allocated_cpus():
    first = parse_state({"cpu": {"usage": 1_000_000_000}})
    second = parse_state({"cpu": {"usage": 2_000_000_000}})
    assert cpu_percent_between(first, second, 1.0, 2) == 50.0
    assert cpu_percent_between(first, second, 0, 2) is None
    assert cpu_percent_between(second, first, 1.0, 2) is None
    assert cpu_percent_between(first, second, 1.0, None) is None


def test_local_metrics_unwraps_cli_envelope():
    service = LocalIncus.__new__(LocalIncus)
    service.api = None
    calls = []
    def query(*args):
        calls.append(args)
        return {"metadata": {"status": "Running", "cpu": {"usage": 42}}}
    service._json = query
    assert service.metrics("dev-vm").cpu_ns == 42
    assert calls == [("query", "/1.0/instances/dev-vm/state")]
    with pytest.raises(ValueError): service.metrics("bad/name")
