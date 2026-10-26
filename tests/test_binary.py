from binascii import unhexlify
from collections.abc import Callable
from typing import Any

import pytest

from srptools import SRPClientSession, SRPContext, SRPException, SRPServerSession
from srptools.constants import HASH_SHA_1, HASH_SHA_256
from srptools.utils import hex_from_b64, int_from_hex, value_encode


def test_full_handshake_binary():
    """Full SRP handshake with bytes input at every IO boundary."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    # Convert hex outputs to bytes for binary path.
    verifier_bin = unhexlify(password_verifier)
    salt_bin = unhexlify(salt)

    # Server accepts bytes verifier.
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier=verifier_bin)
    server_public_bin = server_session.public_bin

    # Client processes bytes public + bytes salt.
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
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

    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier=verifier_bin)
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))

    client_session.process(server_session.public_bin, salt_bin)
    server_session.process(client_session.public_bin, salt_bin)

    # Server verifies client's M (bytes).
    assert server_session.verify_proof(client_session.key_proof_bin)
    # Client verifies server's H(A|M|K) (bytes).
    assert client_session.verify_proof(server_session.key_proof_hash_bin)


def test_session_restore_via_bytes_private():
    """Session restored with private=<bytes> reproduces the same public."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, _ = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    verifier_bin = unhexlify(password_verifier)

    original_server = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier=password_verifier
    )
    server_private_bin = original_server.private_bin

    restored_server = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier=verifier_bin, private=server_private_bin
    )
    assert restored_server.public_bin == original_server.public_bin

    original_client = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_private_bin = original_client.private_bin

    restored_client = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen), private=client_private_bin
    )
    assert restored_client.public_bin == original_client.public_bin


def test_server_accepts_int_verifier():
    """SRPServerSession accepts int password_verifier directly."""
    context = SRPContext('alice', 'password123')
    username, password_verifier, _ = context.get_user_data_triplet()
    prime, gen = context.prime, context.generator

    verifier_int = int_from_hex(password_verifier)

    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier=verifier_int)
    assert server_session.public_bin


@pytest.mark.parametrize("salt_value", [
    pytest.param(0, id="zero"),
    pytest.param(0x0000A1B2C3D4E5F6, id="two-leading-zeros"),
    pytest.param(0x00A1B2C3D4E5F607, id="one-leading-zero"),
    pytest.param(0xA1B2C3D4E5F60708, id="no-leading-zeros"),
])
@pytest.mark.parametrize("hash_func", [HASH_SHA_1, HASH_SHA_256])
def test_get_user_data_triplet_binary(
    monkeypatch: pytest.MonkeyPatch, salt_value: int, hash_func: Callable[..., Any],
) -> None:
    """The verifier must use the exact salt bytes returned to the client."""
    context = SRPContext("alice", "password123", bits_salt=64, hash_func=hash_func)
    monkeypatch.setattr(context, "generate_salt", lambda: salt_value)

    username, verifier, salt = context.get_user_data_triplet(binary=True)

    assert username == "alice"
    assert isinstance(verifier, bytes)
    assert isinstance(salt, bytes)
    # Salt is bits_salt-width (64 bits = 8 bytes).
    assert len(salt) == 8
    assert salt == salt_value.to_bytes(8, "big")
    # Verifier is prime-width (1024-bit prime = 128 bytes).
    assert len(verifier) == 128

    password_hash = hash_func(salt + hash_func(b"alice:password123").digest()).digest()
    expected_verifier = pow(int(context.generator, 16), int.from_bytes(password_hash, "big"), int(context.prime, 16))
    assert int.from_bytes(verifier, "big") == expected_verifier

    server_session = SRPServerSession(SRPContext(username, hash_func=hash_func), password_verifier=verifier)
    client_session = SRPClientSession(SRPContext(username, "password123", hash_func=hash_func))
    client_session.process(server_session.public_bin, salt)
    server_session.process(client_session.public_bin, salt)

    assert client_session.key_bin == server_session.key_bin
    assert server_session.verify_proof(client_session.key_proof_bin)
    assert client_session.verify_proof(server_session.key_proof_hash_bin)

    client_proof = client_session.key_proof_bin
    server_proof = server_session.key_proof_hash_bin
    assert not server_session.verify_proof(bytes([client_proof[0] ^ 1]) + client_proof[1:])
    assert not client_session.verify_proof(bytes([server_proof[0] ^ 1]) + server_proof[1:])


@pytest.mark.parametrize("base64", [False, True])
def test_get_user_data_triplet_preserves_legacy_salt(monkeypatch: pytest.MonkeyPatch, *, base64: bool) -> None:
    context = SRPContext("alice", "password123")
    monkeypatch.setattr(context, "generate_salt", lambda: 0x00A1B2C3D4E5F607)

    _, verifier, salt = context.get_user_data_triplet(base64=base64)

    if base64:
        verifier, salt = hex_from_b64(verifier), hex_from_b64(salt)

    assert salt == "a1b2c3d4e5f607"
    password_hash = context.get_common_password_hash(unhexlify(salt))
    assert int_from_hex(verifier) == context.get_common_password_verifier(password_hash)


@pytest.mark.parametrize("base64", [False, True])
def test_binary_triplet_encoded_handshake(monkeypatch: pytest.MonkeyPatch, *, base64: bool) -> None:
    context = SRPContext("alice", "password123")
    monkeypatch.setattr(context, "generate_salt", lambda: 0x00A1B2C3D4E5F607)
    username, verifier, salt = context.get_user_data_triplet(binary=True)

    server_session = SRPServerSession(SRPContext(username), password_verifier=verifier)
    client_session = SRPClientSession(SRPContext(username, "password123"))
    salt_encoded = value_encode(salt, base64=base64)
    client_session.process(value_encode(server_session.public_bin, base64=base64), salt_encoded, base64=base64)
    server_session.process(value_encode(client_session.public_bin, base64=base64), salt_encoded, base64=base64)

    assert client_session.key_bin == server_session.key_bin
    assert server_session.verify_proof(value_encode(client_session.key_proof_bin, base64=base64), base64=base64)
    assert client_session.verify_proof(value_encode(server_session.key_proof_hash_bin, base64=base64), base64=base64)


def test_binary_triplet_rejects_wrong_password(monkeypatch: pytest.MonkeyPatch) -> None:
    context = SRPContext("alice", "password123")
    monkeypatch.setattr(context, "generate_salt", lambda: 0x00A1B2C3D4E5F607)
    username, verifier, salt = context.get_user_data_triplet(binary=True)

    server_session = SRPServerSession(SRPContext(username), password_verifier=verifier)
    client_session = SRPClientSession(SRPContext(username, "wrong-password"))
    client_session.process(server_session.public_bin, salt)
    server_session.process(client_session.public_bin, salt)

    assert client_session.key_bin != server_session.key_bin
    assert not server_session.verify_proof(client_session.key_proof_bin)
    assert not client_session.verify_proof(server_session.key_proof_hash_bin)


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
        SRPContext(username, prime=prime, generator=gen), password_verifier=password_verifier
    )
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))

    with pytest.raises(SRPException):
        client_session.process(server_session.public_bin, salt_bin, base64=True)


def test_init_common_secret_rejects_garbage_str():
    """init_common_secret raises SRPException on non-hex str."""
    context = SRPContext('alice', 'password123')
    server_session = SRPServerSession(context, password_verifier='1')
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
    server_hex = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier=password_verifier)
    server_private_bin = server_hex.private_bin

    client_hex = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_private_bin = client_hex.private_bin

    client_hex.process(server_hex.public, salt)
    server_hex.process(client_hex.public, salt)
    hex_key = client_hex.key_bin

    # Binary path: restore sessions with the same privates, feed bytes.
    server_bin = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier=verifier_bin, private=server_private_bin
    )
    client_bin = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen), private=client_private_bin
    )

    client_bin.process(server_bin.public_bin, salt_bin)
    server_bin.process(client_bin.public_bin, salt_bin)
    bin_key = client_bin.key_bin

    assert hex_key == bin_key
