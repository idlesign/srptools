from __future__ import division

import click

from . import VERSION, SRPContext, SRPServerSession, SRPClientSession, hex_from_b64


@click.group()
@click.version_option(version='.'.join(map(str, VERSION)))
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


@base.group()
def server():
    """Server session related commands."""


@base.group()
def client():
    """Client session related commands."""


@server.command()
@click.argument('username')
@click.argument('password_verifier')
@click.option('--private', default=None, help='Server private')
def get_private_and_public(username, password_verifier, private):
    """Print out server public and private."""
    session = SRPServerSession(
        SRPContext(username), hex_from_b64(password_verifier), private=hex_from_b64(private))
    click.secho('Server private: %s' % session.private_b64)
    click.secho('Server public: %s' % session.public_b64)


@server.command()
@click.argument('username')
@click.argument('password_verifier')
@click.argument('salt')
@click.argument('client_public')
@click.option('--private', default=None, help='Server private')
def get_session_data(username, password_verifier, salt, client_public, private):
    """Print out server session data."""
    session = SRPServerSession(
        SRPContext(username), hex_from_b64(password_verifier), private=hex_from_b64(private))
    session.process(client_public, salt, base64=True)

    click.secho('Server session key: %s' % session.key_b64)
    click.secho('Server session key proof: %s' % session.key_proof_b64)
    click.secho('Server session key hash: %s' % session.key_proof_hash_b64)


@client.command()
@click.argument('username')
@click.argument('password')
@click.option('--private', default=None, help='Client private')
def get_private_and_public(username, password, private):
    """Print out server public and private."""
    session = SRPClientSession(SRPContext(username, password), private=hex_from_b64(private))
    click.secho('Client private: %s' % session.private_b64)
    click.secho('Client public: %s' % session.public_b64)


@client.command()
@click.argument('username')
@click.argument('password')
@click.argument('salt')
@click.argument('server_public')
@click.option('--private', default=None, help='Client private')
def get_session_data(username, password, salt, server_public, private):
    """Print out client session data."""
    session = SRPClientSession(SRPContext(username, password), private=hex_from_b64(private))
    session.process(server_public, salt, base64=True)

    click.secho('Client session key: %s' % session.key_b64)
    click.secho('Client session key proof: %s' % session.key_proof_b64)
    click.secho('Client session key hash: %s' % session.key_proof_hash_b64)


@base.command()
@click.argument('username')
@click.argument('password')
def get_user_data_triplet(username, password):
    """Print out user data triplet: username, password verifier, salt."""
    context = SRPContext(username, password)
    username, password_verifier, salt = context.get_user_data_triplet(base64=True)

    click.secho('Username: %s' % username)
    click.secho('Password verifier: %s' % password_verifier)
    click.secho('Salt: %s' % salt)


def main():
    """
    CLI entry point
    """
    base(obj={})
