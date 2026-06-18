from __future__ import unicode_literals

from binascii import unhexlify

from six import integer_types

from .exceptions import SRPException
from .utils import hex_from, int_from_hex, int_from_bytes, hex_from_b64, value_encode, b64_from

if False:  # pragma: no cover
    from .context import SRPContext


class SRPSessionBase(object):
    """Base session class for server and client."""

    role = None

    def __init__(self, srp_context, private=None):
        """
        :param SRPContext srp_context:
        :param int|bytes|str private: Private value. Accepts int (binary path),
        bytes (big-endian), or hex string.
        """
        self._context = srp_context

        self._salt = None  # type: bytes
        self._common_secret = None  # type: int
        self._key = None  # type: bytes
        self._key_proof = None  # type: bytes
        self._key_proof_hash = None  # type: bytes

        self._server_public = None  # type: int
        self._client_public = None  # type: int

        self._this_private = None  # type: int

        if private:
            if isinstance(private, integer_types):
                self._this_private = private  # type: int
            elif isinstance(private, bytes):
                self._this_private = int_from_bytes(private)  # type: int
            else:
                self._this_private = int_from_hex(private)  # type: int

    @property
    def _this_public(self):
        return getattr(self, '_%s_public' % self.role)

    def _other_public(self, val):
        other = ('server' if self.role == 'client' else 'client')
        setattr(self, '_%s_public' % other, val)

    _other_public = property(None, _other_public)

    @property
    def private(self):
        return hex_from(self._this_private)

    @property
    def private_bin(self):
        return self._context.pad(self._this_private)

    @property
    def private_b64(self):
        return b64_from(self._this_private)

    @property
    def public(self):
        return hex_from(self._this_public)

    @property
    def public_b64(self):
        return b64_from(self._this_public)

    @property
    def public_bin(self):
        return self._context.pad(self._this_public)

    @property
    def key(self):
        return hex_from(self._key)

    @property
    def key_b64(self):
        return b64_from(self._key)

    @property
    def key_bin(self):
        # -> bytes
        return self._key

    @property
    def key_proof(self):
        return hex_from(self._key_proof)

    @property
    def key_proof_b64(self):
        return b64_from(self._key_proof)

    @property
    def key_proof_bin(self):
        # -> bytes
        return self._key_proof

    @property
    def key_proof_hash(self):
        return hex_from(self._key_proof_hash)

    @property
    def key_proof_hash_b64(self):
        return b64_from(self._key_proof_hash)

    @property
    def key_proof_hash_bin(self):
        # -> bytes
        return self._key_proof_hash

    @classmethod
    def _value_decode(cls, value, base64=False):
        """Decodes value into hex string optionally from base64."""
        return hex_from_b64(value) if base64 else value

    def process(self, other_public, salt, base64=False):
        if base64 and (isinstance(other_public, bytes) or isinstance(salt, bytes)):
            raise SRPException(
                'Cannot decode base64 from bytes. If the value is bytes, it is already decoded and should not be treated as base64.')
        salt = self._value_decode(salt, base64)
        other_public = self._value_decode(other_public, base64)

        self.init_base(salt)
        self.init_common_secret(other_public)
        self.init_session_key()
        self.init_session_key_proof()

        key = value_encode(self._key, base64)
        key_proof = value_encode(self._key_proof, base64)
        key_proof_hash = value_encode(self._key_proof_hash, base64)

        return key, key_proof, key_proof_hash

    def init_base(self, salt):
        if isinstance(salt, bytes):
            self._salt = salt
        else:
            self._salt = unhexlify(salt)

    def init_session_key(self):
        """"""

    def verify_proof(self, key_prove, base64=False):
        """"""

    def init_common_secret(self, other_public):
        """Compute common secret from the other party's public value.

        Accepts:

        - ``int``: used directly (binary path).
        - ``bytes``: big-endian, converted to int.
        - ``str``: hex string.

        .. warning::
            Base64 input is NOT supported. The caller (e.g. :meth:`process`)
            is responsible for decoding base64 to hex before calling this
            method. Passing a base64 string directly will be treated as hex,
            producing a silently corrupted session key.

        :raises SRPException: if the value cannot be decoded or if
            ``other_public % prime == 0`` (RFC 2945 §3).
        """

        if isinstance(other_public, integer_types):
            pass
        elif isinstance(other_public, bytes):
            other_public = int_from_bytes(other_public)
        else:
            # str must be hex, not base64. If the caller passed base64, this will produce a wrong session key, but that's their problem.
            try:
                other_public = int(other_public, 16)
            except (ValueError, TypeError) as e:
                raise SRPException(
                    'Wrong public provided for %s: cannot decode value: %s' % (self.__class__.__name__, e))
        if other_public % self._context._prime == 0:
            raise SRPException('Wrong public provided for %s.' % self.__class__.__name__)
        self._other_public = other_public
        self._common_secret = self._context.get_common_secret(self._server_public, self._client_public)

    def init_session_key_proof(self):
        proof = self._context.get_common_session_key_proof(
            self._key, self._salt, self._server_public, self._client_public)
        self._key_proof = proof

        self._key_proof_hash = self._context.get_common_session_key_proof_hash(self._key, proof, self._client_public)
