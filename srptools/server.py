from __future__ import unicode_literals

from six import integer_types

from .common import SRPSessionBase
from .utils import int_from_hex, int_from_bytes

if False:  # pragma: no cover
    from .context import SRPContext


class SRPServerSession(SRPSessionBase):

    role = 'server'

    def __init__(self, srp_context, password_verifier, private=None):
        """
        :param SRPContext srp_context:
        :param int|bytes|str password_verifier:
        :param int|bytes|str private:
        """
        super(SRPServerSession, self).__init__(srp_context, private)

        if isinstance(password_verifier, bytes):
            self._password_verifier = int_from_bytes(password_verifier)
        elif isinstance(password_verifier, integer_types):
            self._password_verifier = password_verifier
        else:
            self._password_verifier = int_from_hex(password_verifier)

        if not private:
            self._this_private = srp_context.generate_server_private()

        self._server_public = srp_context.get_server_public(self._password_verifier, self._this_private)

    def init_session_key(self):
        super(SRPServerSession, self).init_session_key()

        premaster_secret = self._context.get_server_premaster_secret(
            self._password_verifier, self._this_private, self._client_public, self._common_secret)

        self._key = self._context.get_common_session_key(premaster_secret)

    def verify_proof(self, key_proof, base64=False):
        super(SRPServerSession, self).verify_proof(key_proof)
        if isinstance(key_proof, bytes):
            return key_proof == self._key_proof
        return self._value_decode(key_proof, base64) == self.key_proof
