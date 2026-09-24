"""Small read-only Incus REST client over an already-authorized Unix socket."""
from __future__ import annotations

import http.client
import json
from pathlib import Path
import re
import socket
from typing import Any


class ApiError(RuntimeError):
    pass


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, socket_path: Path) -> None:
        super().__init__("incus", timeout=8)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.socket_path))


class IncusUnixApi:
    ALLOWED = {"/1.0", "/1.0/instances?recursion=2", "/1.0/storage-pools?recursion=1",
               "/1.0/networks?recursion=1"}
    INSTANCE_STATE = re.compile(r"/1\.0/instances/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?/state\Z")
    STORAGE_RESOURCES = re.compile(r"/1\.0/storage-pools/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?/resources\Z")

    def __init__(self, socket_path: Path) -> None:
        if not socket_path.is_socket():
            raise ApiError("Socket Incus inexistente")
        self.socket_path = socket_path

    def get(self, endpoint: str) -> Any:
        if endpoint not in self.ALLOWED and not self.INSTANCE_STATE.fullmatch(endpoint) and not self.STORAGE_RESOURCES.fullmatch(endpoint):
            raise ApiError("Endpoint não autorizado pelo adaptador")
        connection = _UnixHTTP(self.socket_path)
        try:
            connection.request("GET", endpoint, headers={"Accept": "application/json"})
            response = connection.getresponse()
            data = response.read(8_000_001)
            if len(data) > 8_000_000:
                raise ApiError("Resposta Incus grande demais")
            if response.status != 200:
                raise ApiError(f"Incus HTTP {response.status}")
            envelope = json.loads(data)
            if not isinstance(envelope, dict) or envelope.get("type") == "error":
                raise ApiError("Resposta Incus inválida")
            return envelope.get("metadata")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ApiError(f"Falha na API Unix Incus: {exc}") from exc
        finally:
            connection.close()
