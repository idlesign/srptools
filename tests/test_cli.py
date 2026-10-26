from base64 import b64decode
from getpass import GetPassWarning
from warnings import warn

import pytest
from click.testing import CliRunner

from srptools import SRPContext
from srptools.cli import PRESETS, base


@pytest.mark.parametrize("preset", [pytest.param(None, id="default"), *PRESETS])
@pytest.mark.parametrize("hidden_input", [False, True])
def test_cli_handshake(preset: str | None, *, hidden_input: bool) -> None:
    runner = CliRunner()

    def secret_argument(value: str) -> str:
        return "-" if hidden_input else value

    def invoke_command(args: list[str], secrets: tuple[str, ...]) -> dict[str, str]:
        input_text = "\n".join(secrets) + "\n" if hidden_input else None
        result = runner.invoke(base, args, input=input_text)
        assert result.exit_code == 0, result.output or repr(result.exception)
        assert "Warning: diagnostic output includes" in result.stderr
        assert "Warning:" not in result.stdout
        assert "password123" not in result.output
        assert ("command-line arguments may be exposed" in result.stderr) is not hidden_input
        return dict(line.split(": ", 1) for line in result.stdout.strip().splitlines())

    options = ["--preset", preset] if preset else []
    password = secret_argument("password123")
    data = invoke_command(["get-user-data-triplet", *options, "alice", password], ("password123",))
    username, verifier, salt = data["Username"], data["Password verifier"], data["Salt"]

    prime, generator = PRESETS[preset or "1024"]
    context = SRPContext(username, "password123", prime=prime, generator=generator)
    expected_verifier = context.get_common_password_verifier(context.get_common_password_hash(b64decode(salt)))
    assert int.from_bytes(b64decode(verifier), "big") == expected_verifier

    server = invoke_command([
        "server", "get-private-and-public", *options, username, secret_argument(verifier),
    ], (verifier,))
    client = invoke_command(["client", "get-private-and-public", *options, username, password], ("password123",))
    client_data = invoke_command([
        "client", "get-session-data", *options, "--private", secret_argument(client["Client private"]),
        username, password, salt, server["Server public"],
    ], (client["Client private"], "password123"))
    server_data = invoke_command([
        "server", "get-session-data", *options, "--private", secret_argument(server["Server private"]),
        username, secret_argument(verifier), salt, client["Client public"],
    ], (server["Server private"], verifier))

    for field in ("session key", "session key proof", "session key hash"):
        assert client_data[f"Client {field}"] == server_data[f"Server {field}"]


@pytest.mark.parametrize("args", [
    ["get-user-data-triplet", "alice", "password123"],
    ["server", "get-private-and-public", "alice", "AQ=="],
    ["client", "get-private-and-public", "alice", "password123"],
    ["server", "get-session-data", "alice", "AQ==", "AQ==", "Ag=="],
    ["client", "get-session-data", "alice", "password123", "AQ==", "Ag=="],
])
def test_cli_rejects_unknown_preset(args: list[str]) -> None:
    result = CliRunner().invoke(base, [*args, "--preset", "unknown"])

    assert result.exit_code == 2
    assert "Invalid value" in result.output


def test_cli_accepts_literal_dash_password_at_hidden_prompt() -> None:
    result = CliRunner().invoke(base, ["get-user-data-triplet", "alice", "-"], input="-\n")

    assert result.exit_code == 0, result.output
    data = dict(line.split(": ", 1) for line in result.stdout.strip().splitlines())
    context = SRPContext("alice", "-")
    expected_verifier = context.get_common_password_verifier(context.get_common_password_hash(b64decode(data["Salt"])))
    assert int.from_bytes(b64decode(data["Password verifier"]), "big") == expected_verifier


@pytest.mark.parametrize("args", [
    ["get-user-data-triplet", "alice", "-"],
    ["client", "get-private-and-public", "alice", "-"],
    ["client", "get-session-data", "alice", "-", "AQ==", "Ag=="],
    ["server", "get-private-and-public", "alice", "-"],
    ["server", "get-session-data", "alice", "-", "AQ==", "Ag=="],
    ["client", "get-private-and-public", "--private", "-", "alice", "-"],
])
def test_cli_aborts_without_output_when_secret_input_ends(args: list[str]) -> None:
    result = CliRunner().invoke(base, args, input="")

    assert result.exit_code == 1
    assert "Aborted" in result.stderr
    assert result.stdout == ""


def test_cli_refuses_visible_secret_input(monkeypatch: pytest.MonkeyPatch) -> None:

    def prompt_without_terminal(label: str, *, hide_input: bool, err: bool) -> str:
        assert hide_input
        assert err
        warn("Password input may be echoed.", GetPassWarning, stacklevel=2)
        pytest.fail("The secret must not be read after the echo warning.")

    monkeypatch.setattr("srptools.cli.click.prompt", prompt_without_terminal)

    result = CliRunner().invoke(base, ["get-user-data-triplet", "alice", "-"])

    assert result.exit_code == 1
    assert "Hidden input is unavailable" in result.stderr
    assert result.stdout == ""
