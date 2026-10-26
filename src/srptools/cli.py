from collections import OrderedDict
from collections.abc import Callable
from getpass import GetPassWarning
from typing import Any
from warnings import catch_warnings, simplefilter

import click

from . import VERSION, SRPClientSession, SRPContext, SRPServerSession, hex_from_b64
from .constants import (
    PRIME_1024,
    PRIME_1024_GEN,
    PRIME_1536,
    PRIME_1536_GEN,
    PRIME_2048,
    PRIME_2048_GEN,
    PRIME_3072,
    PRIME_3072_GEN,
    PRIME_4096,
    PRIME_4096_GEN,
    PRIME_6144,
    PRIME_6144_GEN,
)

PRESETS = OrderedDict([
    ('1024', (PRIME_1024, PRIME_1024_GEN)),
    ('1536', (PRIME_1536, PRIME_1536_GEN)),
    ('2048', (PRIME_2048, PRIME_2048_GEN)),
    ('3072', (PRIME_3072, PRIME_3072_GEN)),
    ('4096', (PRIME_4096, PRIME_4096_GEN)),
    ('6144', (PRIME_6144, PRIME_6144_GEN)),
])


@click.group()
@click.version_option(version=VERSION)
def base() -> None:
    """srptools diagnostic command line utility.

    Tools to implement Secure Remote Password (SRP) authentication.
    Output includes secrets; do not share or log it.
    Pass '-' instead of a secret argument to enter it without echo.

    Basic scenario:

        > srptools get-user-data-triplet

        > srptools server get-private-and-public

        > srptools client get-private-and-public

        > srptools client get-session-data

        > srptools server get-session-data

    """
    click.echo(
        "Warning: diagnostic output includes password verifiers, private values and session keys. "
        "Use only in a trusted environment; do not share or log it.",
        err=True,
    )


def read_secret(value: str, label: str) -> str:
    """Read '-' values without echo, or warn about secrets supplied in arguments."""

    if value != "-":
        click.echo(
            f"Warning: {label} in command-line arguments may be exposed in shell history or process listings. "
            "Pass '-' for hidden input instead.",
            err=True,
        )
        return value

    try:

        with catch_warnings():
            # getpass must not fall back to reading a secret with terminal echo enabled.
            simplefilter("error", GetPassWarning)
            return click.prompt(label, hide_input=True, err=True)

    except GetPassWarning:
        raise click.ClickException(
            "Hidden input is unavailable; use a terminal that supports disabling echo.",
        ) from None


def add_preset_option(func: Callable[..., Any]) -> Callable[..., Any]:
    """Group selection shared by registration and session commands."""

    def parse_preset(
        ctx: click.Context, param: click.Parameter, value: str | None,
    ) -> tuple[str | None, str | None]:
        return PRESETS.get(value, (None, None))

    return click.option(
        "--preset",
        default=None, help="Preset ID defining prime and generator pair.",
        type=click.Choice(PRESETS.keys()), callback=parse_preset
    )(func)


def common_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Commonly used command options."""

    def parse_private(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
        return hex_from_b64(read_secret(value, "Private value")) if value else None

    func = click.option(
        "--private", default=None, help="Base64 private value, or '-' for hidden input.", callback=parse_private,
    )(func)
    return add_preset_option(func)


@base.group()
def server():
    """Server session related commands."""


@base.group()
def client():
    """Client session related commands."""


@server.command(name="get-private-and-public")
@click.argument("username")
@click.argument("password_verifier")
@common_options
def get_server_private_and_public(
    username: str, password_verifier: str, private: str | None, preset: tuple[str | None, str | None],
) -> None:
    """Print out server public and private."""
    password_verifier = read_secret(password_verifier, "Password verifier")
    session = SRPServerSession(
        SRPContext(username, prime=preset[0], generator=preset[1]),
        password_verifier=hex_from_b64(password_verifier), private=private)

    click.secho(f"Server private: {session.private_b64}")
    click.secho(f"Server public: {session.public_b64}")


@server.command(name="get-session-data")
@click.argument("username")
@click.argument("password_verifier")
@click.argument("salt")
@click.argument("client_public")
@common_options
def get_server_session_data(
    username: str,
    password_verifier: str,
    salt: str,
    client_public: str,
    private: str | None,
    preset: tuple[str | None, str | None],
) -> None:
    """Print out server session data."""
    password_verifier = read_secret(password_verifier, "Password verifier")
    session = SRPServerSession(
        SRPContext(username, prime=preset[0], generator=preset[1]),
        password_verifier=hex_from_b64(password_verifier), private=private)

    session.process(other_public=client_public, salt=salt, base64=True)

    click.secho(f"Server session key: {session.key_b64}")
    click.secho(f"Server session key proof: {session.key_proof_b64}")
    click.secho(f"Server session key hash: {session.key_proof_hash_b64}")


@client.command(name="get-private-and-public")
@click.argument("username")
@click.argument("password")
@common_options
def get_client_private_and_public(
    username: str, password: str, private: str | None, preset: tuple[str | None, str | None],
) -> None:
    """Print out client public and private."""
    password = read_secret(password, "Password")
    session = SRPClientSession(
        SRPContext(username, password, prime=preset[0], generator=preset[1]),
        private=private)

    click.secho(f"Client private: {session.private_b64}")
    click.secho(f"Client public: {session.public_b64}")


@client.command(name="get-session-data")
@click.argument("username")
@click.argument("password")
@click.argument("salt")
@click.argument("server_public")
@common_options
def get_client_session_data(
    username: str,
    password: str,
    salt: str,
    server_public: str,
    private: str | None,
    preset: tuple[str | None, str | None],
) -> None:
    """Print out client session data."""
    password = read_secret(password, "Password")
    session = SRPClientSession(
        SRPContext(username, password, prime=preset[0], generator=preset[1]),
        private=private)

    session.process(other_public=server_public, salt=salt, base64=True)

    click.secho(f"Client session key: {session.key_b64}")
    click.secho(f"Client session key proof: {session.key_proof_b64}")
    click.secho(f"Client session key hash: {session.key_proof_hash_b64}")


@base.command()
@click.argument("username")
@click.argument("password")
@add_preset_option
def get_user_data_triplet(username: str, password: str, preset: tuple[str | None, str | None]) -> None:
    """Print out user data triplet: username, password verifier, salt."""
    password = read_secret(password, "Password")
    context = SRPContext(username, password, prime=preset[0], generator=preset[1])
    username, password_verifier, salt = context.get_user_data_triplet(base64=True)

    click.secho(f"Username: {username}")
    click.secho(f"Password verifier: {password_verifier}")
    click.secho(f"Salt: {salt}")


def main():
    """
    CLI entry point
    """
    base(obj={})
