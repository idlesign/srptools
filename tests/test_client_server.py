from collections.abc import Callable
from secrets import compare_digest
from typing import Any

import pytest

from srptools import SRPClientSession, SRPContext, SRPException, SRPServerSession
from srptools.constants import HASH_SHA_1, HASH_SHA_256
from srptools.utils import b64_from, int_from_hex, value_encode


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
    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier=password_verifier)
    server_public = server_session.public
    server_public_b64 = server_session.public_b64
    server_private = server_session.private
    assert server_session.private_b64

    # Receive server public and salt and process them.
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_session.process(other_public=server_public, salt=salt)
    # Generate client public and session key proof.
    client_public = client_session.public
    client_public_b64 = client_session.public_b64
    client_session_key_proof = client_session.key_proof
    client_private = client_session.private
    assert client_session.private_b64

    # Process client public and verify session key proof.
    server_session.process(other_public=client_public, salt=salt)
    assert server_session.verify_proof(client_session_key_proof)
    # Generate session key proof hash.
    server_session_key_proof_hash = server_session.key_proof_hash

    # Verify session key proff hash received from server.
    assert client_session.verify_proof(server_session_key_proof_hash)

    assert client_session.key_b64
    assert client_session.key_proof_b64
    assert client_session.key_proof_hash_b64

    # Restore sessions from privates.
    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier=password_verifier,
        private=server_private)
    client_session = SRPClientSession(
        SRPContext(username, 'password123', prime=prime, generator=gen),
        private=client_private)

    skey_cl, skey_proof_cl, _ = client_session.process(other_public=server_public, salt=salt)
    skey_srv, skey_proof_srv, _ = server_session.process(other_public=client_public, salt=salt)

    assert skey_cl == skey_srv
    assert skey_proof_cl == skey_proof_srv

    # Base 64 test
    skey_cl, skey_proof_cl, _ = client_session.process(other_public=server_public_b64, salt=salt_b64, base64=True)
    skey_srv, skey_proof_srv, _ = server_session.process(other_public=client_public_b64, salt=salt_b64, base64=True)

    assert skey_cl == skey_srv
    assert skey_proof_cl == skey_proof_srv


def test_simple():
    # Agree on communication details.
    context = SRPContext('alice', 'password123')
    username, password_verifier, salt = context.get_user_data_triplet()
    prime = context.prime
    gen = context.generator

    # Receive username from client and generate server public.
    server_session = SRPServerSession(
        SRPContext(username, prime=prime, generator=gen), password_verifier=password_verifier)
    server_public = server_session.public

    # Receive server public and salt and process them.
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_session.process(other_public=server_public, salt=salt)
    # Generate client public and session key.
    client_public = client_session.public
    client_session_key = client_session.key

    # Process client public and compare session keys.
    server_session.process(other_public=client_public, salt=salt)
    server_session_key = server_session.key

    assert server_session_key == client_session_key


def test_raises():
    server_session = SRPServerSession(SRPContext('1', '2'), password_verifier='1')
    server_session._context._prime = 1  # to trigger error
    with pytest.raises(SRPException):
        server_session.init_common_secret('1')

    client_session = SRPClientSession(SRPContext('1', '2'))
    client_session._context._prime = 1  # to trigger error
    with pytest.raises(SRPException):
        client_session.init_common_secret('1')


@pytest.mark.parametrize(("encode_proof", "use_base64"), [
    pytest.param(bytes, False, id="binary"),
    pytest.param(bytes.hex, False, id="hex"),
    pytest.param(b64_from, True, id="base64"),
])
@pytest.mark.parametrize("hash_func", [HASH_SHA_1, HASH_SHA_256])
def test_verify_proof_uses_timing_resistant_comparison(
    monkeypatch: pytest.MonkeyPatch,
    encode_proof: Callable[[bytes], str | bytes],
    hash_func: Callable[..., Any],
    *,
    use_base64: bool,
) -> None:
    context = SRPContext("alice", "password123", hash_func=hash_func)
    username, verifier, salt = context.get_user_data_triplet()
    server_session = SRPServerSession(SRPContext(username, hash_func=hash_func), password_verifier=verifier)
    client_session = SRPClientSession(context)
    client_session.process(server_session.public, salt)
    server_session.process(client_session.public, salt)
    comparisons = []

    def compare_proofs(received: str | bytes, expected: str | bytes) -> bool:
        comparisons.append((received, expected))
        return compare_digest(received, expected)

    monkeypatch.setattr("srptools.client.compare_digest", compare_proofs)
    monkeypatch.setattr("srptools.server.compare_digest", compare_proofs)

    for session, proof in (
        (server_session, client_session.key_proof_bin),
        (client_session, server_session.key_proof_hash_bin),
    ):
        encoded_proof = encode_proof(proof)
        assert session.verify_proof(encoded_proof, base64=use_base64)
        expected = proof if isinstance(encoded_proof, bytes) else proof.hex()
        assert comparisons.pop() == (expected, expected)

        for invalid_proof in (
            bytes([proof[0] ^ 1]) + proof[1:],
            proof[:-1] + bytes([proof[-1] ^ 1]),
            proof[:-1],
            proof + b"\x00",
            b"",
        ):
            assert not session.verify_proof(encode_proof(invalid_proof), base64=use_base64)
            assert len(comparisons) == 1
            comparisons.clear()

        assert not session.verify_proof("not-a-proof")
        assert not session.verify_proof("\N{SNOWMAN}")
        assert not session.verify_proof("\ud800")
        comparisons.clear()
