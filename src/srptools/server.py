from __future__ import annotations

from secrets import compare_digest
from typing import TYPE_CHECKING

from .common import SRPSessionBase
from .utils import int_from_bytes, int_from_hex

if TYPE_CHECKING:
    from .context import SRPContext


class SRPServerSession(SRPSessionBase):

    role = 'server'

    def __init__(self, srp_context: SRPContext, *, password_verifier: str | int | bytes, private: str | int | bytes = ''):
        super().__init__(srp_context, private)

        if isinstance(password_verifier, int):
            self._password_verifier = password_verifier
        elif isinstance(password_verifier, bytes):
            self._password_verifier = int_from_bytes(password_verifier)
        else:
            self._password_verifier = int_from_hex(password_verifier)

        if not private:
            self._this_private = srp_context.generate_server_private()

        self._server_public = srp_context.get_server_public(
            password_verifier=self._password_verifier,
            server_private=self._this_private
        )

    def init_session_key(self) -> None:
        super().init_session_key()

        premaster_secret = self._context.get_server_premaster_secret(
            password_verifier=self._password_verifier,
            server_private=self._this_private,
            client_public=self._client_public,
            common_secret=self._common_secret
        )

        self._key = self._context.get_common_session_key(premaster_secret)

    def verify_proof(self, key_proof: str | bytes, *, base64: bool = False) -> bool:
        super().verify_proof(key_proof)

        if isinstance(key_proof, bytes):
            return compare_digest(key_proof, self._key_proof)

        return self._value_decode(key_proof, base64=base64) == self.key_proof
