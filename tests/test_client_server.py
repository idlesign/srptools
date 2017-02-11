from srptools import SRPContext, SRPClientSession, SRPServerSession


def test_extended():

    # Preliminary steps.
    context = SRPContext('alice', 'password123')
    # Generate basic user auth data usually stored on server.
    username, password_verifier, salt = context.get_user_data_triplet()
    # And gather basic numbers for client and server to agree upon.
    prime = context.prime
    gen = context.generator

    # Actual negotiation

    # Receive username from client and generate server public.
    server_session = SRPServerSession(SRPContext(username, prime=prime, generator=gen), password_verifier)
    server_public = server_session.public

    # Receive server public and salt and process them.
    client_session = SRPClientSession(SRPContext(username, 'password123', prime=prime, generator=gen))
    client_session.process(server_public, salt)
    # Generate client public and session key proof.
    client_public = client_session.public
    client_session_key_proof = client_session.key_proof

    # Process client public and verify session key proof.
    server_session.process(client_public, salt)
    assert server_session.verify_proof(client_session_key_proof)
    # Generate session key proof hash.
    server_session_key_proof_hash = client_session.key_proof_hash

    # Verify session key proff hash received from server.
    assert client_session.verify_proof(server_session_key_proof_hash)

    skey_cl, skey_proof_cl, skey_prove_hash_cl = client_session.process(server_public, salt)
    skey_srv, skey_proof_srv, skey_prove_hash_srv = server_session.process(client_public, salt)

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
