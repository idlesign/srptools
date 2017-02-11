from .common import SRPSessionBase
from .utils import int_from_hex


if False:
    from .context import SRPContext


class SRPServerSession(SRPSessionBase):

    role = 'server'

    def __init__(self, srp_context, password_verifier):
        """
        :param SRPContext srp_context:
        """
        super(SRPServerSession, self).__init__(srp_context)
        self._context.password = None

        self._password_verifier = int_from_hex(password_verifier)

        self._server_private = srp_context.generate_server_private()
        self._server_public = srp_context.get_server_public(self._password_verifier, self._server_private)

    def init_session_key(self):
        super(SRPServerSession, self).init_session_key()

        premaster_secret = self._context.get_server_premaster_secret(
            self._password_verifier, self._server_private, self._client_public, self._common_secret)

        self._key = self._context.get_common_session_key(premaster_secret)

    def verify_proof(self, key_proof, base64=False):
        super(SRPServerSession, self).verify_proof(key_proof)

        return self._value_decode(key_proof, base64) == self.key_proof
