from __future__ import unicode_literals
from binascii import unhexlify

import pytest

from srptools import SRPContext, SRPClientSession, SRPServerSession, SRPException


def test_full_handshake_binary():
    """Full SRP handshake with bytes input at every IO boundary."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    # Convert hex outputs to bytes for binary path.
    verifier_bin = unhexlify(password_verifier)
    salt_bin = unhexlify(salt)

    # Server accepts bytes verifier.
    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), verifier_bin)
    server_public_bin = server_session.public_bin

    # Client processes bytes public + bytes salt.
    client_session = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen))
    client_session.process(server_public_bin, salt_bin)
    client_public_bin = client_session.public_bin

    # Server processes bytes public + bytes salt.
    server_session.process(client_public_bin, salt_bin)

    # Session keys and proofs match.
    assert client_session.key_bin == server_session.key_bin
    assert client_session.key_proof_bin == server_session.key_proof_bin
    assert client_session.key_proof_hash_bin == server_session.key_proof_hash_bin


def test_verify_proof_binary():
    """verify_proof accepts bytes proofs on both sides."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    salt_bin = unhexlify(salt)
    verifier_bin = unhexlify(password_verifier)

    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), verifier_bin)
    client_session = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen))

    client_session.process(server_session.public_bin, salt_bin)
    server_session.process(client_session.public_bin, salt_bin)

    # Server verifies client's M (bytes).
    assert server_session.verify_proof(client_session.key_proof_bin)
    # Client verifies server's H(A|M|K) (bytes).
    assert client_session.verify_proof(server_session.key_proof_hash_bin)


def test_session_restore_via_bytes_private():
    """Session restored with private=<bytes> reproduces the same public."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    verifier_bin = unhexlify(password_verifier)

    original_server = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier)
    server_private_bin = original_server.private_bin

    restored_server = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), verifier_bin,
        private=server_private_bin)
    assert restored_server.public_bin == original_server.public_bin

    original_client = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen))
    client_private_bin = original_client.private_bin

    restored_client = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen),
        private=client_private_bin)
    assert restored_client.public_bin == original_client.public_bin


def test_server_accepts_int_verifier():
    """SRPServerSession accepts int password_verifier directly."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    from srptools.utils import int_from_hex
    verifier_int = int_from_hex(password_verifier)

    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), verifier_int)
    assert server_session.public_bin


def test_get_user_data_triplet_binary():
    """get_user_data_triplet(binary=True) emits bytes verifier and salt."""
    context = SRPContext('alice', 'password123', bits_salt=64)

    username, verifier, salt = context.get_user_data_triplet(binary=True)

    assert username == 'alice'
    assert isinstance(verifier, bytes)
    assert isinstance(salt, bytes)
    # Salt is bits_salt-width (64 bits = 8 bytes).
    assert len(salt) == 8
    # Verifier is prime-width (1024-bit prime = 128 bytes).
    assert len(verifier) == 128


def test_get_user_data_triplet_binary_mutual_exclusion():
    """binary=True and base64=True together must raise."""
    context = SRPContext('alice', 'password123')
    with pytest.raises(SRPException):
        context.get_user_data_triplet(base64=True, binary=True)


def test_process_bytes_base64_mutual_exclusion():
    """process() must reject bytes input with base64=True."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    salt_bin = unhexlify(salt)
    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier)
    client_session = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen))

    with pytest.raises(SRPException):
        client_session.process(server_session.public_bin, salt_bin, base64=True)


def test_init_common_secret_rejects_garbage_str():
    """init_common_secret raises SRPException on non-hex str."""
    context = SRPContext('alice', 'password123')
    server_session = SRPServerSession(context, '1')
    with pytest.raises(SRPException):
        server_session.init_common_secret('not-hex-at-all')


def test_binary_path_matches_hex_path():
    """Binary handshake produces the same session key as hex handshake,
    given the same private values and salt.
    """
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    salt_bin = unhexlify(salt)
    verifier_bin = unhexlify(password_verifier)

    # Hex path: capture privates to reuse in binary path.
    server_hex = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier)
    server_private_bin = server_hex.private_bin

    client_hex = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen))
    client_private_bin = client_hex.private_bin

    client_hex.process(server_hex.public, salt)
    server_hex.process(client_hex.public, salt)
    hex_key = client_hex.key_bin

    # Binary path: restore sessions with the same privates, feed bytes.
    server_bin = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), verifier_bin,
        private=server_private_bin)
    client_bin = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen),
        private=client_private_bin)

    client_bin.process(server_bin.public_bin, salt_bin)
    server_bin.process(client_bin.public_bin, salt_bin)
    bin_key = client_bin.key_bin

    assert hex_key == bin_key
