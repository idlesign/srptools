from __future__ import annotations

from typing import TYPE_CHECKING

from .common import SRPSessionBase
from .utils import int_from_hex

if TYPE_CHECKING:
    from .context import SRPContext


class SRPServerSession(SRPSessionBase):

    role = 'server'

    def __init__(self, srp_context: SRPContext, *, password_verifier: str, private: str = ''):
        super().__init__(srp_context, private)

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

    def verify_proof(self, key_proof: str, *, base64: bool = False) -> bool:
        super().verify_proof(key_proof)

        return self._value_decode(key_proof, base64=base64) == self.key_proof
