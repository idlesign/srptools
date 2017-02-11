from __future__ import unicode_literals
import pytest

from srptools import SRPContext, SRPClientSession, SRPServerSession, SRPException
from srptools.utils import int_from_hex, value_encode


def test_extended():

    # Preliminary steps.
    context = SRPContext('alice', 'password123')
    # Generate basic user auth data usually stored on server.
    username, password_verifier, salt = context.get_user_data_triplet()
    # And gather basic numbers for client and server to agree upon.
    prime = context.prime
    gen = context.generator

    salt_b64 = value_encode(int_from_hex(salt), base64=True)

    # Actual negotiation

    # Receive username from client and generate server public.
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier)
    server_public = server_session.public
    server_public_b64 = server_session.public_b64
    server_private = server_session.private
    assert server_session.private_b64

    # Receive server public and salt and process them.
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_session.process(server_public, salt)
    # Generate client public and session key proof.
    client_public = client_session.public
    client_public_b64 = client_session.public_b64
    client_session_key_proof = client_session.key_proof
    client_private = client_session.private
    assert client_session.private_b64

    # Process client public and verify session key proof.
    server_session.process(client_public, salt)
    assert server_session.verify_proof(client_session_key_proof)
    # Generate session key proof hash.
    server_session_key_proof_hash = client_session.key_proof_hash

    # Verify session key proff hash received from server.
    assert client_session.verify_proof(server_session_key_proof_hash)

    assert client_session.key_b64
    assert client_session.key_proof_b64
    assert client_session.key_proof_hash_b64

    # Restore sessions from privates.
    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier,
        private=server_private)
    client_session = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen),
        private=client_private)

    skey_cl, skey_proof_cl, skey_prove_hash_cl = client_session.process(server_public, salt)
    skey_srv, skey_proof_srv, skey_prove_hash_srv = server_session.process(client_public, salt)

    assert skey_cl == skey_srv
    assert skey_proof_cl == skey_proof_srv

    # Base 64 test
    skey_cl, skey_proof_cl, skey_prove_hash_cl = client_session.process(server_public_b64, salt_b64, base64=True)
    skey_srv, skey_proof_srv, skey_prove_hash_srv = server_session.process(client_public_b64, salt_b64, base64=True)

    assert skey_cl == skey_srv
    assert skey_proof_cl == skey_proof_srv


def test_simple():
    # Agree on communication details.
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime = context.prime
    gen = context.generator

    # Receive username from client and generate server public.
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier)
    server_public = server_session.public

    # Receive server public and salt and process them.
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_session.process(server_public, salt)
    # Generate client public and session key.
    client_public = client_session.public
    client_session_key = client_session.key

    # Process client public and compare session keys.
    server_session.process(client_public, salt)
    server_session_key = server_session.key

    assert server_session_key == client_session_key


def test_raises():
    server_session = SRPServerSession(SRPContext('1', '2'), '1')
    server_session._context._prime = 1  # to trigger error
    with pytest.raises(SRPException):
        server_session.init_common_secret('1')

    client_session = SRPClientSession(SRPContext('1', '2'))
    client_session._context._prime = 1  # to trigger error
    with pytest.raises(SRPException):
        client_session.init_common_secret('1')
