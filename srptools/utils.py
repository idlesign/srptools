from __future__ import unicode_literals
from binascii import unhexlify, hexlify
from base64 import b64encode, b64decode

from six import integer_types


def value_encode(val, base64=False):
    """Encodes int into hex or base64."""
    return int_to_b64(val) if base64 else hex_from(val)


def hex_from_b64(val):
    """Returns hex string representation for base64 encoded value.

    :param str val:
    :rtype: bytes|str
    """
    return hex_from(b64decode(val))


def hex_from(val):
    """Returns hex string representation for a given value.

    :param bytes|str|unicode|int|long val:
    :rtype: bytes|str
    """
    if isinstance(val, integer_types):
        return '%x' % val

    return hexlify(val)


def int_from_hex(hexstr):
    """Returns int/long representation for a given hex string.

    :param bytes|str|unicode hexstr:
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
    :rtype: bytes|str
    """
    return b64encode(int_to_bytes(val)).decode('ascii')
