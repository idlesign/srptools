# Usage hints

* `srptools.constants` contains basic constants which can be used with `SRPContext` for server and client to agree
  upon communication details.
* `.process()` methods of session classes may raise `SRPException` in certain circumstances. Auth process on
  such occasions must be stopped.
* `.private` attribute of session classes may be used to restore sessions:

    ```python
    server_private = server_session.private

    # Restore session on new request.
    server_session = SRPServerSession(context, password_verifier, private=server_private)
    ```

* `SRPContext` is rather flexible, so you can implement some custom server/client session logic with its help.
* Basic values are represented as hex strings but base64 encoded values are also supported:

    ```python
    server_public = server_session.public_b64

    # Receive server public and salt and process them.
    client_session = SRPClientSession(SRPContext('alice', 'password123', prime=prime, generator=gen))
    client_session.process(server_public, salt, base64=True)

    # Use srptools.hex_from_b64() to represent base64 value as hex.
    server_public_hex = hex_from_b64(server_public)
    ```
