# API usage

## Preliminary step

Agree on communication details:

```python
from srptools import SRPContext

context = SRPContext('alice', 'password123')
username, password_verifier, salt = context.get_user_data_triplet()
prime = context.prime
gen = context.generator
```

!!! note
    `get_user_data_triplet()` returns hex-encoded `password_verifier` and `salt` by default.
    Use `base64=True` to get base64-encoded values instead.
    Use `binary=True` to get raw bytes, with a prime-width verifier and a padded salt.
    The binary verifier is derived from the exact returned salt bytes, including leading zeros.
    `binary` and `base64` are mutually exclusive.

## Simplified workflow

This local example illustrates key agreement, not authentication. Never transmit session keys to compare them.
For authentication, use the proof checks in the extended workflow below.

```python
from srptools import SRPContext, SRPClientSession, SRPException, SRPServerSession

# Receive username from client and generate server public.
server_session = SRPServerSession(
    SRPContext(username, prime=prime, generator=gen),
    password_verifier=password_verifier,
)
server_public = server_session.public

# Receive server public and salt and process them.
client_session = SRPClientSession(SRPContext("alice", "password123", prime=prime, generator=gen))
client_session.process(other_public=server_public, salt=salt)
# Generate client public and session key.
client_public = client_session.public

# Process client public and compare session keys.
server_session.process(other_public=client_public, salt=salt)

if server_session.key != client_session.key:
    raise SRPException("Local key agreement failed.")
```

## Extended workflow

`process()` computes keys and proofs; it does not authenticate the peer.
Verify the client's proof before sending the server's proof, and verify the server's proof before trusting it.
Do not use the session keys for application data until authentication succeeds.
On failure, abort authentication and discard the session. Do not use `assert` for authentication checks:
Python removes assertions when run with `-O` or `-OO`.

```python
from srptools import SRPContext, SRPClientSession, SRPException, SRPServerSession

# Receive username from client and generate server public.
server_session = SRPServerSession(
    SRPContext(username, prime=prime, generator=gen),
    password_verifier=password_verifier,
)
server_public = server_session.public

# Receive server public and salt and process them.
client_session = SRPClientSession(SRPContext("alice", "password123", prime=prime, generator=gen))
client_session.process(other_public=server_public, salt=salt)
# Generate client public and session key proof.
client_public = client_session.public
client_session_key_proof = client_session.key_proof

# Process client public and verify session key proof.
server_session.process(other_public=client_public, salt=salt)

if not server_session.verify_proof(client_session_key_proof):
    raise SRPException("Client authentication failed.")

# Only send the server's proof after authenticating the client.
server_session_key_proof_hash = server_session.key_proof_hash

# Verify session key proof hash received from server.

if not client_session.verify_proof(server_session_key_proof_hash):
    raise SRPException("Server authentication failed.")
```
