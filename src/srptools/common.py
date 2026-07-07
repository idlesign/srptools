from __future__ import annotations

from binascii import unhexlify
from typing import TYPE_CHECKING

from .exceptions import SRPException
from .utils import b64_from, hex_from, hex_from_b64, int_from_bytes, int_from_hex, value_encode

if TYPE_CHECKING:
    from .context import Salt, SRPContext


class SRPSessionBase:
    """Base session class for server and client."""

    role: str | None = None

    def __init__(self, srp_context: SRPContext, private: str | int | bytes = '') -> None:
        self._context = srp_context

        self._salt: Salt | None = None
        self._common_secret: int | None = None
        self._key: bytes | None = None
        self._key_proof: bytes | None = None
        self._key_proof_hash: bytes | None = None

        self._server_public: int | None = None
        self._client_public: int | None = None

        self._this_private: int | None = None

        if private:
            if isinstance(private, int):
                self._this_private = private
            elif isinstance(private, bytes):
                self._this_private = int_from_bytes(private)
            else:
                self._this_private = int_from_hex(private)

    @property
    def _this_public(self) -> int:
        return getattr(self, f'_{self.role}_public')

    def _other_public(self, val: int) -> None:
        other = 'server' if self.role == 'client' else 'client'
        setattr(self, f'_{other}_public', val)

    _other_public = property(None, _other_public)

    @property
    def private(self) -> str:
        return hex_from(self._this_private)

    @property
    def private_b64(self) -> str:
        return b64_from(self._this_private)

    @property
    def private_bin(self) -> bytes:
        return self._context.pad(self._this_private)

    @property
    def public(self) -> str:
        return hex_from(self._this_public)

    @property
    def public_b64(self) -> str:
        return b64_from(self._this_public)

    @property
    def public_bin(self) -> bytes:
        return self._context.pad(self._this_public)

    @property
    def key(self) -> str:
        return hex_from(self._key)

    @property
    def key_b64(self) -> str:
        return b64_from(self._key)

    @property
    def key_bin(self) -> bytes:
        return self._key

    @property
    def key_proof(self) -> str:
        return hex_from(self._key_proof)

    @property
    def key_proof_b64(self) -> str:
        return b64_from(self._key_proof)

    @property
    def key_proof_bin(self) -> bytes:
        return self._key_proof

    @property
    def key_proof_hash(self) -> str:
        return hex_from(self._key_proof_hash)

    @property
    def key_proof_hash_b64(self) -> str:
        return b64_from(self._key_proof_hash)

    @property
    def key_proof_hash_bin(self) -> bytes:
        return self._key_proof_hash

    @classmethod
    def _value_decode(cls, value: str | bytes, *, base64: bool = False) -> str | bytes:
        """Decodes value into hex optionally from base64."""
        if base64:
            if isinstance(value, bytes):
                raise SRPException('Cannot decode base64 from bytes.')
            return hex_from_b64(value)
        return value

    def process(
        self,
        other_public: str | bytes = '',
        salt: str | bytes = '',
        *,
        base64: bool = False,
    ) -> tuple[str, str, str]:
        if base64 and (isinstance(other_public, bytes) or isinstance(salt, bytes)):
            raise SRPException(
                'Cannot decode base64 from bytes. '
                'If the value is bytes, it is already decoded and should not be treated as base64.'
            )
        salt = self._value_decode(salt, base64=base64)
        other_public = self._value_decode(other_public, base64=base64)

        self.init_base(salt)
        self.init_common_secret(other_public)
        self.init_session_key()
        self.init_session_key_proof()

        key = value_encode(self._key, base64=base64)
        key_proof = value_encode(self._key_proof, base64=base64)
        key_proof_hash = value_encode(self._key_proof_hash, base64=base64)

        return key, key_proof, key_proof_hash

    def init_base(self, salt: str | bytes) -> None:
        if isinstance(salt, bytes):
            self._salt = salt
        else:
            self._salt = unhexlify(salt)

    def init_session_key(self) -> None:
        pass

    def verify_proof(self, key_prove: str | bytes, *, base64: bool = False) -> bool:
        pass

    def init_common_secret(self, other_public: str | int | bytes) -> None:
        if isinstance(other_public, int):
            pass
        elif isinstance(other_public, bytes):
            other_public = int_from_bytes(other_public)
        else:
            try:
                other_public = int(other_public, 16)
            except (ValueError, TypeError) as e:
                raise SRPException(
                    f'Wrong public provided for {self.__class__.__name__}: cannot decode value: {e}',
                ) from e

        if other_public % self._context._prime == 0:  # A % N is zero | B % N is zero
            raise SRPException(f'Wrong public provided for {self.__class__.__name__}.')

        self._other_public = other_public

        self._common_secret = self._context.get_common_secret(self._server_public, self._client_public)

    def init_session_key_proof(self) -> None:
        proof = self._context.get_common_session_key_proof(
            session_key=self._key, salt=self._salt, server_public=self._server_public, client_public=self._client_public
        )

        self._key_proof = proof

        self._key_proof_hash = self._context.get_common_session_key_proof_hash(
            session_key=self._key, session_key_proof=proof, client_public=self._client_public
        )
