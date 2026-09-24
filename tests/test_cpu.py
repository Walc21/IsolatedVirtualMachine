import pytest

from isolatevm.cpu import CPUSelectionError, cpu_ids, format_cpu_set, parse_cpu_set


def test_cpu_selection_parser_preserves_single_thread_identity():
    assert parse_cpu_set("0-2,6") == (0, 1, 2, 6)
    assert format_cpu_set((0, 1, 2, 6)) == "0-2,6-6"
    assert format_cpu_set((6,)) == "6-6"


@pytest.mark.parametrize("value", ["", " 1", "1, 2", "1-0", "1,1", "0-64", "4096", "1;2"])
def test_cpu_selection_parser_rejects_ambiguous_or_unbounded_values(value):
    with pytest.raises(CPUSelectionError):
        parse_cpu_set(value)


def test_cpu_inventory_uses_thread_ids_and_omits_offline_or_isolated_threads():
    resources = {"cpu": {"total": 4, "sockets": [{"socket": 0, "cores": [
        {"core": 0, "threads": [
            {"id": 0, "thread": 0, "online": True, "isolated": False},
            {"id": 1, "thread": 1, "online": True, "isolated": True}]},
        {"core": 1, "threads": [
            {"id": 2, "thread": 0, "online": True},
            {"id": 3, "thread": 1, "online": False}]}]}]}}
    assert cpu_ids(resources) == (0, 2)
