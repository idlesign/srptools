from .common import SRPSessionBase


if False:
    from .context import SRPContext


class SRPClientSession(SRPSessionBase):

    role = 'client'

    def __init__(self, srp_context):
        """
        :param SRPContext srp_context:
        """
        super(SRPClientSession, self).__init__(srp_context)

        self._password_hash = None

        self._client_private = srp_context.generate_client_private()
        self._client_public = srp_context.get_client_public(self._client_private)

    def init_base(self, salt):
        super(SRPClientSession, self).init_base(salt)

        self._password_hash = self._context.get_common_password_hash(self._salt)

    def init_session_key(self):
        super(SRPClientSession, self).init_session_key()

        premaster_secret = self._context.get_client_premaster_secret(
            self._password_hash, self._server_public, self._client_private, self._common_secret)

        self._key = self._context.get_common_session_key(premaster_secret)

    def verify_proof(self, key_proof, base64=False):
        super(SRPClientSession, self).verify_proof(key_proof)

        return self._value_decode(key_proof, base64) == self.key_proof_hash
