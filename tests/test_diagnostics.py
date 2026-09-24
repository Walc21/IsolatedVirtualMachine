from isolatevm import diagnostics


def test_diagnostic_incus_environment_is_local_and_does_not_forward_credentials(
        monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(diagnostics, "data_dir", lambda: data_dir)
    monkeypatch.setenv("OPENAI_API_KEY", "host-secret")
    monkeypatch.setenv("INCUS_REMOTE", "untrusted-remote")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/untrusted.so")

    environment = diagnostics._incus_client_environment()

    assert environment["INCUS_CONF"] == str(tmp_path / "data" / "incus-client")
    assert environment["PATH"] == diagnostics.CLIENT_PATH
    assert not {"OPENAI_API_KEY", "INCUS_REMOTE", "LD_PRELOAD"} & environment.keys()
