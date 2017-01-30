from binascii import unhexlify
from base64 import b64encode

from six import string_types


def get_hexstr(val):
    """Returns hex string representation for a given value.

    :param bytes|str|unicode|int|long val:
    :rtype: bytes|str
    """
    if isinstance(val, string_types):
        return val.encode('hex')

    return '%x' % val


def int_from_hexstr(hexstr):
    """Returns int/long representation for a given hex string.

    :param bytes|str hexstr:
    :rtype: int|long
    """
    return int(hexstr, 16)


def int_to_bytes(val):
    """Returns bytes representation for a given int/long.

    :param int|long val:
    :rtype: bytes|str
    """
    hex_str = '%x' % val
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return unhexlify(hex_str)


def int_to_b64(val):
    """Returns base64 encoded bytes for a given int/long.

    :param int|long val:
    :rtype: str
    """
    return b64encode(int_to_bytes(val))
