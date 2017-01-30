from random import SystemRandom as random

from six import integer_types

from .utils import int_from_hexstr, int_to_bytes
from .constants import PRIME_1024, PRIME_1024_GEN, HASH_SHA_1


# todo .get_client_session_key_hash()
# todo .get_server_session_key_hash()


class SRPContext(object):
    """

    * The SRP Authentication and Key Exchange System
        https://tools.ietf.org/html/rfc2945

    * Using the Secure Remote Password (SRP) Protocol for TLS Authentication
        https://tools.ietf.org/html/rfc5054

    """
    def __init__(
            self, username, password, prime=None, generator=None, hash_func=None, multiplier=None,
            bits_random=1024, bits_salt=64):

        self.hash_func = hash_func or HASH_SHA_1
        self.username = username  # I
        self.password = password  # p

        self.generator = int_from_hexstr(generator or PRIME_1024_GEN)  # g
        self.prime = int_from_hexstr(prime or PRIME_1024)  # N
        self.multiplier = (  # k = SHA1(N | PAD(g))
            int_from_hexstr(multiplier) if multiplier else self.hash(self.prime, self.pad(self.generator)))

        self.bits_salt = bits_salt
        self.bits_random = bits_random

    def pad(self, val):
        """
        :param val:
        :rtype: bytes
        """
        padding = len(int_to_bytes(self.prime))
        padded = int_to_bytes(val).rjust(padding, str('\x00'))
        return padded

    def hash(self, *args, **kwargs):
        joiner = str(kwargs.get('joiner', ''))

        def conv(arg):
            if isinstance(arg, integer_types):
                arg = int_to_bytes(arg)
            return str(arg)

        digest = joiner.join(map(conv, args))
        return int_from_hexstr(self.hash_func(digest).hexdigest())

    def generate_random(self, bits_len=None):
        bits_len = bits_len or self.bits_random
        return random().getrandbits(bits_len)

    def generate_salt(self):
        """s = random

        :return:
        """
        return self.generate_random(self.bits_salt)

    def get_common_secret(self, server_public, client_public):
        """u = SHA1(PAD(A) | PAD(B))

        :param server_public:
        :param client_public:
        :return:
        """
        return self.hash(self.pad(client_public), self.pad(server_public))

    def get_client_premaster_secret(self, password_hash, server_public, client_private, common_secret):
        """S = (B - (k * g^x)) ^ (a + (u * x)) % N

        :param server_public:
        :param password_hash:
        :param client_private:
        :param common_secret:
        :return:
        """
        password_verifier = self.get_password_verifier(password_hash)
        return pow(
            (server_public - (self.multiplier * password_verifier)),
            (client_private + (common_secret * password_hash)), self.prime)

    def get_session_key(self, premaster_secret):
        """K = H(S)

        :param premaster_secret:
        :return: int -- not bytes!
        :rtype: int
        """
        return self.hash(premaster_secret)

    def get_server_premaster_secret(self, password_verifier, server_private, client_public, common_secret):
        """S = (A * v^u) ^ b % N

        :param password_verifier:
        :param server_private:
        :param client_public:
        :param common_secret:
        :return:
        """
        return pow((client_public * pow(password_verifier, common_secret, self.prime)), server_private, self.prime)

    def generate_client_private(self):
        """a = random()

        :return:
        """
        return self.generate_random()

    def generate_server_private(self):
        """b = random()

        :return:
        """
        return self.generate_random()

    def get_client_public(self, client_private):
        """A = g^a % N

        :param client_private:
        :return:
        """
        return pow(self.generator, client_private, self.prime)

    def get_server_public(self, password_verifier, server_private):
        """B = (k*v + g^b) % N

        :param password_verifier:
        :param server_private:
        :return:
        """
        return ((self.multiplier * password_verifier) + pow(self.generator, server_private, self.prime)) % self.prime

    def get_password_hash(self, salt):
        """x = SHA1(s | SHA1(I | ":" | P))

        :param salt:
        :return:
        """
        return self.hash(salt, self.hash(self.username, self.password, joiner=':'))

    def get_password_verifier(self, password_hash):
        """v = g^x % N

        :param password_hash:
        :return:
        """
        return pow(self.generator, password_hash, self.prime)
