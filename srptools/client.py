from base64 import b64encode, b64decode

from .utils import get_hexstr, int_to_bytes, int_from_hexstr
from .exceptions import SRPClientException


if False:
    from .context import SRPContext


class SRPClientSession(object):

    def __init__(self, srp_context):
        """
        :param SRPContext srp_context:
        """
        self._context = srp_context
        self._private = srp_context.generate_client_private()
        self._public = srp_context.get_client_public(self._private)

        self._server_public = None
        self._password_hash = None
        self._common_secret = None
        self._premaster_secret = None
        self._key = None

    @property
    def public_hexstr(self):
        return get_hexstr(self._public)

    @property
    def public_bytes(self):
        return int_to_bytes(self._public)

    @property
    def key_hexstr(self):
        return get_hexstr(self._key)

    @property
    def key_bytes(self):
        return int_to_bytes(self._key)

    def process(self, salt, server_public, base64=False):
        if base64:
            salt = get_hexstr(b64decode(salt))
            server_public = get_hexstr(b64decode(server_public))

        self.init_password_hash(salt)
        self.init_common_secret(server_public)
        self.init_session_key()

        if base64:
            session_key = b64encode(self.key_bytes)
            client_public = b64encode(self.public_bytes)
        else:
            session_key = self.key_hexstr
            client_public = self.public_hexstr

        return client_public, session_key

    def init_password_hash(self, salt):
        salt = int_from_hexstr(salt)
        password_hash = self._context.get_password_hash(salt)
        self._password_hash = password_hash
        return password_hash

    def init_common_secret(self, server_public):
        server_public = int_from_hexstr(server_public)

        if not server_public % self._context.prime:  # server: A % N is zero
            raise SRPClientException('Wrong server public.')

        common_secret = self._context.get_common_secret(server_public, self._public)

        self._common_secret = common_secret
        self._server_public = server_public

        return common_secret

    def init_session_key(self):
        premaster_secret = self._context.get_client_premaster_secret(
            self._password_hash, self._server_public, self._private, self._common_secret)

        self._premaster_secret = premaster_secret

        session_key = self._context.get_session_key(premaster_secret)
        self._key = session_key

        return session_key
