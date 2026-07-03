from collections import OrderedDict

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
def base():
    """srptools command line utility.

    Tools to implement Secure Remote Password (SRP) authentication.

    Basic scenario:

        > srptools get_user_data_triplet

        > srptools server get_private_and_public

        > srptools client get_private_and_public

        > srptools client get_session_data

        > srptools server get_session_data

    """

def common_options(func):
    """Commonly used command options."""

    def parse_preset(ctx, param, value):
        return PRESETS.get(value, (None, None))

    def parse_private(ctx, param, value):
        return hex_from_b64(value) if value else None

    func = click.option('--private', default=None, help='Private.', callback=parse_private)(func)

    func = click.option(
        '--preset',
        default=None, help='Preset ID defining prime and generator pair.',
        type=click.Choice(PRESETS.keys()), callback=parse_preset
    )(func)

    return func


@base.group()
def server():
    """Server session related commands."""


@base.group()
def client():
    """Client session related commands."""


@server.command(name='get-private-and-public')
@click.argument('username')
@click.argument('password_verifier')
@common_options
def get_server_private_and_public(username, password_verifier, private, preset):
    """Print out server public and private."""
    session = SRPServerSession(
        SRPContext(username, prime=preset[0], generator=preset[1]),
        password_verifier=hex_from_b64(password_verifier), private=private)

    click.secho(f'Server private: {session.private_b64}')
    click.secho(f'Server public: {session.public_b64}')


@server.command(name='get-session-data')
@click.argument('username')
@click.argument('password_verifier')
@click.argument('salt')
@click.argument('client_public')
@common_options
def get_server_session_data(username, password_verifier, salt, client_public, private, preset):
    """Print out server session data."""
    session = SRPServerSession(
        SRPContext(username, prime=preset[0], generator=preset[1]),
        password_verifier=hex_from_b64(password_verifier), private=private)

    session.process(other_public=client_public, salt=salt, base64=True)

    click.secho(f'Server session key: {session.key_b64}')
    click.secho(f'Server session key proof: {session.key_proof_b64}')
    click.secho(f'Server session key hash: {session.key_proof_hash_b64}')


@client.command(name='get-private-and-public')
@click.argument('username')
@click.argument('password')
@common_options
def get_client_private_and_public(ctx, username, password, private, preset):
    """Print out server public and private."""
    session = SRPClientSession(
        SRPContext(username, password, prime=preset[0], generator=preset[1]),
        private=private)

    click.secho(f'Client private: {session.private_b64}')
    click.secho(f'Client public: {session.public_b64}')


@client.command(name='get-session-data')
@click.argument('username')
@click.argument('password')
@click.argument('salt')
@click.argument('server_public')
@common_options
def get_client_session_data(ctx, username, password, salt, server_public, private, preset):
    """Print out client session data."""
    session = SRPClientSession(
        SRPContext(username, password, prime=preset[0], generator=preset[1]),
        private=private)

    session.process(other_public=server_public, salt=salt, base64=True)

    click.secho(f'Client session key: {session.key_b64}')
    click.secho(f'Client session key proof: {session.key_proof_b64}')
    click.secho(f'Client session key hash: {session.key_proof_hash_b64}')


@base.command()
@click.argument('username')
@click.argument('password')
def get_user_data_triplet(username, password):
    """Print out user data triplet: username, password verifier, salt."""
    context = SRPContext(username, password)
    username, password_verifier, salt = context.get_user_data_triplet(base64=True)

    click.secho(f'Username: {username}')
    click.secho(f'Password verifier: {password_verifier}')
    click.secho(f'Salt: {salt}')


def main():
    """
    CLI entry point
    """
    base(obj={})
