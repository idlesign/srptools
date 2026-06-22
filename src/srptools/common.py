from __future__ import annotations

from binascii import unhexlify
from typing import TYPE_CHECKING

from .exceptions import SRPException
from .utils import b64_from, hex_from, hex_from_b64, int_from_hex, value_encode

if TYPE_CHECKING:
    from .context import Salt, SRPContext


class SRPSessionBase:
    """Base session class for server and client."""

    role: str | None = None

    def __init__(self, srp_context: SRPContext, private: str = '') -> None:
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
            self._this_private = int_from_hex(private)

    @property
    def _this_public(self) -> int:
        return getattr(self, f'_{self.role}_public')

    def _other_public(self, val: int) -> None:
        other = ('server' if self.role == 'client' else 'client')
        setattr(self, f'_{other}_public', val)

    _other_public = property(None, _other_public)

    @property
    def private(self) -> str:
        return hex_from(self._this_private)

    @property
    def private_b64(self) -> str:
        return b64_from(self._this_private)

    @property
    def public(self) -> str:
        return hex_from(self._this_public)

    @property
    def public_b64(self) -> str:
        return b64_from(self._this_public)

    @property
    def key(self) -> str:
        return hex_from(self._key)

    @property
    def key_b64(self) -> str:
        return b64_from(self._key)

    @property
    def key_proof(self) -> str:
        return hex_from(self._key_proof)

    @property
    def key_proof_b64(self) -> str:
        return b64_from(self._key_proof)

    @property
    def key_proof_hash(self) -> str:
        return hex_from(self._key_proof_hash)

    @property
    def key_proof_hash_b64(self) -> str:
        return b64_from(self._key_proof_hash)

    @classmethod
    def _value_decode(cls, value: str, *, base64: bool = False) -> str:
        """Decodes value into hex optionally from base64."""
        return hex_from_b64(value) if base64 else value

    def process(
        self,
        *,
        other_public: str,
        salt: str,
        base64: bool = False,
    ) -> tuple[str, str, str]:
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

    def init_base(self, salt: str) -> None:
        salt = unhexlify(salt)
        self._salt = salt

    def init_session_key(self) -> None:
        pass

    def verify_proof(self, key_prove: str, *, base64: bool = False) -> bool:
        pass

    def init_common_secret(self, other_public: str) -> None:
        other_public = int_from_hex(other_public)

        if other_public % self._context._prime == 0:  # A % N is zero | B % N is zero
            raise SRPException(f'Wrong public provided for {self.__class__.__name__}.')

        self._other_public = other_public

        self._common_secret = self._context.get_common_secret(self._server_public, self._client_public)

    def init_session_key_proof(self) -> None:
        proof = self._context.get_common_session_key_proof(
            session_key=self._key,
            salt=self._salt,
            server_public=self._server_public,
            client_public=self._client_public
        )

        self._key_proof = proof

        self._key_proof_hash = self._context.get_common_session_key_proof_hash(
            session_key=self._key,
            session_key_proof=proof,
            client_public=self._client_public
        )
