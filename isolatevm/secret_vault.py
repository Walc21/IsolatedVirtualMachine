"""Secret Service storage for credentials that never belong in manifests."""
from __future__ import annotations

from contextlib import contextmanager
import re
from typing import Iterator


APP_ATTRIBUTE = "org.isolatevm.IsolateVM"
SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
RESERVED = {"PATH", "HOME", "SHELL", "USER", "LOGNAME", "PWD", "IFS", "ENV",
            "BASH_ENV", "PYTHONPATH", "PYTHONHOME"}
MAX_SECRET_BYTES = 16 * 1024


class SecretVaultError(RuntimeError):
    """Safe, non-sensitive error shown to the operator."""


def validate_secret_name(name: object) -> str:
    if not isinstance(name, str) or not SECRET_NAME.fullmatch(name) or name in RESERVED or name.startswith("LD_"):
        raise SecretVaultError("Nome inválido. Use uma variável em maiúsculas, como OPENAI_API_KEY.")
    return name


def validate_secret_value(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SecretVaultError("O valor do secret precisa ser texto UTF-8 não vazio.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise SecretVaultError("O valor do secret não é texto UTF-8 válido.") from None
    if len(encoded) > MAX_SECRET_BYTES:
        raise SecretVaultError("O secret excede 16 KiB.")
    return value


@contextmanager
def _collection(unlock: bool) -> Iterator[tuple[object, object]]:
    try:
        import secretstorage
    except ImportError:
        raise SecretVaultError("Falta python3-secretstorage; reinstale o pacote IsolateVM.") from None
    try:
        connection = secretstorage.dbus_init()
    except Exception:
        raise SecretVaultError("Não foi possível abrir a sessão D-Bus do usuário para acessar o cofre.") from None
    try:
        if not secretstorage.check_service_availability(connection):
            raise SecretVaultError("Nenhum Secret Service está disponível nesta sessão gráfica.")
        collection = secretstorage.get_default_collection(connection)
        if unlock and collection.is_locked() and collection.unlock():
            raise SecretVaultError("O desbloqueio do cofre foi cancelado.")
        yield secretstorage, collection
    except SecretVaultError:
        raise
    except Exception:
        # D-Bus/provider errors can contain operation details. Never forward them
        # because this boundary handles credential material.
        raise SecretVaultError("O cofre não está disponível ou foi bloqueado.") from None
    finally:
        try:
            connection.close()
        except Exception:
            pass


class SecretVault:
    """Store named UTF-8 values in the desktop's default Secret Service collection."""

    @staticmethod
    def _attributes(name: str) -> dict[str, str]:
        return {"application": APP_ATTRIBUTE, "name": validate_secret_name(name)}

    def names(self) -> list[str]:
        with _collection(unlock=False) as (_, collection):
            names = set()
            for item in collection.search_items({"application": APP_ATTRIBUTE}):
                value = item.get_attributes().get("name", "")
                if SECRET_NAME.fullmatch(value) and value not in RESERVED and not value.startswith("LD_"):
                    names.add(value)
            return sorted(names)

    def store(self, name: str, value: str) -> None:
        name = validate_secret_name(name)
        value = validate_secret_value(value)
        with _collection(unlock=True) as (_, collection):
            collection.create_item(f"IsolateVM · {name}", self._attributes(name), value.encode("utf-8"),
                                   replace=True, content_type="text/plain;charset=utf-8")

    def delete(self, name: str) -> None:
        attributes = self._attributes(name)
        with _collection(unlock=True) as (_, collection):
            for item in list(collection.search_items(attributes)):
                item.delete()

    def get_many(self, names: tuple[str, ...]) -> dict[str, str]:
        requested = tuple(dict.fromkeys(validate_secret_name(name) for name in names))
        if not requested:
            raise SecretVaultError("Este manifesto não referencia secrets.")
        with _collection(unlock=True) as (_, collection):
            items: dict[str, object] = {}
            for item in collection.search_items({"application": APP_ATTRIBUTE}):
                name = item.get_attributes().get("name", "")
                if name in requested:
                    items[name] = item
            missing = [name for name in requested if name not in items]
            if missing:
                raise SecretVaultError("Cadastre no cofre: " + ", ".join(missing))
            result: dict[str, str] = {}
            for name in requested:
                item = items[name]
                if item.is_locked() and item.unlock():
                    raise SecretVaultError("O desbloqueio do cofre foi cancelado.")
                try:
                    value = item.get_secret().decode("utf-8")
                except UnicodeDecodeError:
                    raise SecretVaultError(f"O secret {name} não contém texto UTF-8.") from None
                result[name] = validate_secret_value(value)
            return result
