from collections.abc import Callable
from random import SystemRandom as random
from typing import Any, TypeAlias

from .constants import HASH_SHA_1, PRIME_1024, PRIME_1024_GEN
from .exceptions import SRPException
from .utils import b64_from, hex_from, int_from_hex, int_to_bytes, value_encode

Salt: TypeAlias = int | bytes


class SRPContext:
    """

    * The SRP Authentication and Key Exchange System
        https://tools.ietf.org/html/rfc2945

    * Using the Secure Remote Password (SRP) Protocol for TLS Authentication
        https://tools.ietf.org/html/rfc5054

    """
    def __init__(
        self,
        username: str,
        password: str | None = None,
        *,
        prime: str = '',
        generator: str = '',
        hash_func: Callable[..., Any] | None = None,
        multiplier: str = '',
        bits_random: int = 1024,
        bits_salt: int = 64,
    ):
        """
        :param username: User name
        :param password: User password
        :param prime: Prime hex string . Default: PRIME_1024
        :param generator: Generator hex string. Default: PRIME_1024_GEN
        :param hash_func: Function to calculate hash. Default: HASH_SHA_1
        :param multiplier: Multiplier hex string. If not given will be calculated
            automatically using prime and gen.
        :param bits_random: Random value bits. Default: 1024
        :param bits_salt: Salt value bits. Default: 64
        """
        self._hash_func = hash_func or HASH_SHA_1  # H
        self._user = username  # I
        self._password = password  # p

        self._gen = int_from_hex(generator or PRIME_1024_GEN)  # g
        self._prime = int_from_hex(prime or PRIME_1024)  # N
        self._mult = (  # k = H(N | PAD(g))
            int_from_hex(multiplier) if multiplier else self.hash(self._prime, self.pad(self._gen)))

        self._bits_salt = bits_salt
        self._bits_random = bits_random

    @property
    def generator(self) -> str:
        return hex_from(self._gen)

    @property
    def generator_b64(self) -> str:
        return b64_from(self._gen)

    @property
    def prime(self) -> str:
        return hex_from(self._prime)

    @property
    def prime_b64(self) -> str:
        return b64_from(self._prime)

    def pad(self, val: int) -> bytes:
        padding = len(int_to_bytes(self._prime))
        padded = int_to_bytes(val).rjust(padding, b'\x00')
        return padded

    def hash(
        self,
        *args: int | str | bytes,
        joiner: str = '',
        as_bytes: bool = False,
    ) -> int | bytes:
        joiner_bytes = joiner.encode('utf-8')

        def conv(arg: int | str | bytes) -> bytes:
            if isinstance(arg, int):
                arg = int_to_bytes(arg)

            if isinstance(arg, str):
                arg = arg.encode('utf-8')
            return arg

        digest = joiner_bytes.join(map(conv, args))

        hash_obj = self._hash_func(digest)

        if as_bytes:
            return hash_obj.digest()

        return int_from_hex(hash_obj.hexdigest())

    def generate_random(self, bits_len: int | None = None) -> int:
        """Generates a random value."""
        bits_len = bits_len or self._bits_random
        return random().getrandbits(bits_len)

    def generate_salt(self) -> int:
        """s = random"""
        return self.generate_random(self._bits_salt)

    def get_common_secret(self, server_public: int, client_public: int) -> int:
        """u = H(PAD(A) | PAD(B))"""
        return self.hash(self.pad(client_public), self.pad(server_public))

    def get_client_premaster_secret(
        self,
        *,
        password_hash: int,
        server_public: int,
        client_private: int,
        common_secret: int,
    ) -> int:
        """S = (B - (k * g^x)) ^ (a + (u * x)) % N"""
        password_verifier = self.get_common_password_verifier(password_hash)
        return pow(
            (server_public - (self._mult * password_verifier)),
            (client_private + (common_secret * password_hash)), self._prime)

    def get_common_session_key(self, premaster_secret: int) -> bytes:
        """K = H(S)"""
        return self.hash(premaster_secret, as_bytes=True)

    def get_server_premaster_secret(
        self,
        *,
        password_verifier: int,
        server_private: int,
        client_public: int,
        common_secret: int,
    ) -> int:
        """S = (A * v^u) ^ b % N"""
        return pow((client_public * pow(password_verifier, common_secret, self._prime)), server_private, self._prime)

    def generate_client_private(self) -> int:
        """a = random()"""
        return self.generate_random()

    def generate_server_private(self) -> int:
        """b = random()"""
        return self.generate_random()

    def get_client_public(self, *, client_private: int) -> int:
        """A = g^a % N"""
        return pow(self._gen, client_private, self._prime)

    def get_server_public(self, *, password_verifier: int, server_private: int) -> int:
        """B = (k*v + g^b) % N"""
        return ((self._mult * password_verifier) + pow(self._gen, server_private, self._prime)) % self._prime

    def get_common_password_hash(self, salt: Salt) -> int:
        """x = H(s | H(I | ":" | P))"""
        password = self._password
        if password is None:
            raise SRPException('User password should be in context for this scenario.')

        return self.hash(salt, self.hash(self._user, password, joiner=':', as_bytes=True))

    def get_common_password_verifier(self, password_hash: int) -> int:
        """v = g^x % N"""
        return pow(self._gen, password_hash, self._prime)

    def get_common_session_key_proof(
        self,
        *,
        session_key: bytes,
        salt: Salt,
        server_public: int,
        client_public: int,
    ) -> bytes:
        """M = H(H(N) XOR H(g) | H(U) | s | A | B | K)"""
        h = self.hash
        prove = h(
            h(self._prime) ^ h(self._gen),
            h(self._user),
            salt,
            self.pad(client_public),
            self.pad(server_public),
            session_key,
            as_bytes=True
        )
        return prove

    def get_common_session_key_proof_hash(
        self,
        *,
        session_key: bytes,
        session_key_proof: bytes,
        client_public: int,
    ) -> bytes:
        """H(A | M | K)"""
        return self.hash(client_public, session_key_proof, session_key, as_bytes=True)

    def get_user_data_triplet(
        self,
        *,
        base64: bool = False,
        binary: bool = False,
    ) -> tuple[str, str | bytes, str | bytes]:
        """( <_user>, <_password verifier>, <salt> )

        :param bool base64: Output verifier and salt as base64 strings.
        :param bool binary: Output verifier and salt as raw bytes. Verifier
            is prime-width (padded), salt is bits_salt-width (padded).
            Mutually exclusive with ``base64``.
        :raises SRPException: if both ``base64`` and ``binary`` are True.
        """
        if binary and base64:
            raise SRPException('binary and base64 are mutually exclusive')

        salt = self.generate_salt()
        verifier = self.get_common_password_verifier(self.get_common_password_hash(salt))

        if binary:
            salt_bytes = int_to_bytes(salt).rjust(self._bits_salt // 8, b'\x00')
            return self._user, self.pad(verifier), salt_bytes

        verifier = value_encode(verifier, base64=base64)
        salt = value_encode(salt, base64=base64)

        return self._user, verifier, salt
