from __future__ import annotations

from typing import TYPE_CHECKING

from .common import SRPSessionBase

if TYPE_CHECKING:
    from .context import SRPContext


class SRPClientSession(SRPSessionBase):

    role = 'client'

    def __init__(self, srp_context: SRPContext, *, private: str | int | bytes = ''):
        super().__init__(srp_context, private)

        self._password_hash: int | None = None

        if not private:
            self._this_private = srp_context.generate_client_private()

        self._client_public = srp_context.get_client_public(client_private=self._this_private)

    def init_base(self, salt: str | bytes):
        super().init_base(salt)

        self._password_hash = self._context.get_common_password_hash(self._salt)

    def init_session_key(self):
        super().init_session_key()

        premaster_secret = self._context.get_client_premaster_secret(
            password_hash=self._password_hash,
            server_public=self._server_public,
            client_private=self._this_private,
            common_secret=self._common_secret,
        )

        self._key = self._context.get_common_session_key(premaster_secret)

    def verify_proof(self, key_proof: str | bytes, *, base64: bool = False) -> bool:
        super().verify_proof(key_proof)

        if isinstance(key_proof, bytes):
            return key_proof == self._key_proof_hash

        return self._value_decode(key_proof, base64=base64) == self.key_proof_hash
