import json
from pathlib import Path
import socket
import threading

import pytest

from isolatevm.api import ApiError, IncusUnixApi


def test_unix_api_is_read_only_and_enveloped(tmp_path):
    path = tmp_path / "incus.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path)); server.listen(1)
    requests = []
    def serve():
        conn, _ = server.accept()
        with conn:
            requests.append(conn.recv(4096).decode())
            body = json.dumps({"type": "sync", "metadata": {"api_extensions": []}}).encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body)
        server.close()
    thread = threading.Thread(target=serve); thread.start()
    api = IncusUnixApi(path)
    with pytest.raises(ApiError): api.get("/1.0/instances/victim/state/../delete")
    assert api.INSTANCE_STATE.fullmatch("/1.0/instances/dev-vm/state")
    assert api.STORAGE_RESOURCES.fullmatch("/1.0/storage-pools/default/resources")
    assert api.INSTANCE_SNAPSHOTS.fullmatch("/1.0/instances/dev-vm/snapshots?recursion=1")
    assert api.INSTANCE_SNAPSHOTS.fullmatch(
        "/1.0/instances/dev-vm/snapshots?recursion=1&project=user-1234")
    assert not api.INSTANCE_SNAPSHOTS.fullmatch(
        "/1.0/instances/dev-vm/snapshots?recursion=1&project=default")
    assert api.INSTANCE_SNAPSHOTS.fullmatch("/1.0/instances/dev-vm/snapshots?recursion=1")
    assert api.INSTANCE_SNAPSHOTS.fullmatch(
        "/1.0/instances/dev-vm/snapshots?recursion=1&project=user-1234")
    assert not api.INSTANCE_SNAPSHOTS.fullmatch(
        "/1.0/instances/dev-vm/snapshots?recursion=1&project=default")
    with pytest.raises(ApiError, match="Endpoint"):
        api.get("/1.0/storage-pools/default/../resources")
    assert api.get("/1.0") == {"api_extensions": []}
    thread.join(timeout=2)
    assert requests[0].startswith("GET /1.0 HTTP/1.1")
