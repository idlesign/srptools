from base64 import b64decode, b64encode


def value_encode(val: int | bytes, *, base64: bool = False) -> str:
    """Encodes int into hex or base64."""
    return b64_from(val) if base64 else hex_from(val)


def hex_from_b64(val: str | bytes) -> str:
    """Returns hex string representation for a base64 encoded value."""
    if isinstance(val, bytes):
        val = val.decode('ascii')
    return b64decode(val).hex()


def int_from_bytes(val: bytes) -> int:
    """Returns int representation for a given bytes value (big-endian)."""
    return int.from_bytes(val, 'big')


def hex_from(val: int | bytes) -> str:
    """Returns hex string representation for a given value."""
    if isinstance(val, int):
        return int_to_bytes(val).hex()

    return val.hex()


def int_from_hex(hexstr: str | bytes) -> int:
    """Returns int representation for a given hex string."""
    return int(hexstr, 16)


def int_to_bytes(val: int) -> bytes:
    """Returns bytes representation for a given int."""
    length = (val.bit_length() + 7) // 8 or 1
    return val.to_bytes(length, 'big')


def b64_from(val: int | bytes) -> str:
    """Returns base64 encoded string for a given int/bytes value."""
    if isinstance(val, int):
        val = int_to_bytes(val)
    return b64encode(val).decode('ascii')
