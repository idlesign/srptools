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

## Simplified workflow

```python
from srptools import SRPContext, SRPClientSession, SRPServerSession

# Receive username from client and generate server public.
server_session = SRPServerSession(
    SRPContext(username, prime=prime, generator=gen),
    password_verifier=password_verifier,
)
server_public = server_session.public

# Receive server public and salt and process them.
client_session = SRPClientSession(SRPContext('alice', 'password123', prime=prime, generator=gen))
client_session.process(other_public=server_public, salt=salt)
# Generate client public and session key.
client_public = client_session.public

# Process client public and compare session keys.
server_session.process(other_public=client_public, salt=salt)

assert server_session.key == client_session.key
```

## Extended workflow

```python
from srptools import SRPContext, SRPClientSession, SRPServerSession

# Receive username from client and generate server public.
server_session = SRPServerSession(
    SRPContext(username, prime=prime, generator=gen),
    password_verifier=password_verifier,
)
server_public = server_session.public

# Receive server public and salt and process them.
client_session = SRPClientSession(SRPContext('alice', 'password123', prime=prime, generator=gen))
client_session.process(other_public=server_public, salt=salt)
# Generate client public and session key proof.
client_public = client_session.public
client_session_key_proof = client_session.key_proof

# Process client public and verify session key proof.
server_session.process(other_public=client_public, salt=salt)
assert server_session.verify_proof(client_session_key_proof)
# Generate session key proof hash.
server_session_key_proof_hash = client_session.key_proof_hash

# Verify session key proof hash received from server.
assert client_session.verify_proof(server_session_key_proof_hash)
```
