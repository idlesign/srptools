import pytest

from srptools import SRPContext, SRPClientSession
from srptools.utils import int_from_hexstr, get_hexstr


def test_client():

    static_salt = int_from_hexstr('BEB25379D1A8581EB5A727673A2441EE')

    session = SRPClientSession(SRPContext(
        'alice',
        'password123',
        multiplier='7556AA045AEF2CDD07ABAF0F665C3E818913186F',
    ))
    # todo session.process(static_salt ...)
