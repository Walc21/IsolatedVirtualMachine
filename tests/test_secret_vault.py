from __future__ import annotations

import sys
from types import ModuleType

import pytest

from isolatevm.secret_vault import SecretVault, SecretVaultError, validate_secret_name, validate_secret_value


class FakeItem:
    def __init__(self, attrs, secret):
        self.attrs = attrs
        self.secret = secret
        self.locked = False

    def get_attributes(self):
        return dict(self.attrs)

    def is_locked(self):
        return self.locked

    def unlock(self):
        return False

    def get_secret(self):
        return self.secret

    def delete(self):
        collection.items.remove(self)


class FakeCollection:
    def __init__(self):
        self.items = []
        self.locked = False
        self.dismiss_unlock = False

    def is_locked(self):
        return self.locked

    def unlock(self):
        return self.dismiss_unlock

    def search_items(self, attributes):
        return [item for item in self.items
                if all(item.attrs.get(key) == value for key, value in attributes.items())]

    def create_item(self, label, attributes, secret, replace=False, content_type=None):
        if replace:
            self.items = [item for item in self.items if item.attrs != attributes]
        item = FakeItem(attributes, secret)
        self.items.append(item)
        return item


collection = FakeCollection()


@pytest.fixture
def fake_service(monkeypatch):
    global collection
    collection = FakeCollection()
    module = ModuleType("secretstorage")
    module.dbus_init = lambda: type("Connection", (), {"close": lambda self: None})()
    module.check_service_availability = lambda _connection: True
    module.get_default_collection = lambda _connection: collection
    monkeypatch.setitem(sys.modules, "secretstorage", module)
    return collection


def test_secret_service_storage_lists_names_and_round_trips_values_only_on_request(fake_service):
    vault = SecretVault()
    vault.store("OPENAI_API_KEY", "synthetic-test-value-should-not-be-logged")
    assert vault.names() == ["OPENAI_API_KEY"]
    assert vault.get_many(("OPENAI_API_KEY",)) == {
        "OPENAI_API_KEY": "synthetic-test-value-should-not-be-logged"}
    vault.store("OPENAI_API_KEY", "replacement-test-value")
    assert len(fake_service.items) == 1
    assert vault.get_many(("OPENAI_API_KEY",))["OPENAI_API_KEY"] == "replacement-test-value"
    vault.delete("OPENAI_API_KEY")
    assert vault.names() == []


def test_vault_errors_do_not_include_credential_values(fake_service):
    vault = SecretVault()
    with pytest.raises(SecretVaultError) as error:
        vault.get_many(("GITHUB_TOKEN",))
    assert "GITHUB_TOKEN" in str(error.value)
    assert "synthetic-test-value" not in str(error.value)
    fake_service.locked = True
    fake_service.dismiss_unlock = True
    with pytest.raises(SecretVaultError, match="cancelado") as locked:
        vault.store("GITHUB_TOKEN", "replacement-test-value")
    assert "replacement-test-value" not in str(locked.value)


@pytest.mark.parametrize("name", ["PATH", "LD_PRELOAD", "bad-name", "lowercase", "A" * 65])
def test_secret_names_reject_reserved_or_invalid_environment_keys(name):
    with pytest.raises(SecretVaultError):
        validate_secret_name(name)


def test_secret_values_are_bounded_nonempty_utf8_without_nul():
    assert validate_secret_name("OPENAI_API_KEY") == "OPENAI_API_KEY"
    assert validate_secret_value("síntese") == "síntese"
    for value in ("", "bad\x00value", "x" * (16 * 1024 + 1)):
        with pytest.raises(SecretVaultError):
            validate_secret_value(value)
