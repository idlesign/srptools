from __future__ import unicode_literals
import pytest

from srptools import SRPContext, SRPException
from srptools.utils import int_from_hex, hex_from


def test_context():

    def to_hex_u(val):
        return hex_from(val).upper()

    static_salt = int_from_hex('BEB25379D1A8581EB5A727673A2441EE')
    static_client_private = int_from_hex('60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393')
    static_server_private = int_from_hex('E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20')

    context = SRPContext(
        'alice',
        'password123',
        multiplier='7556AA045AEF2CDD07ABAF0F665C3E818913186F',
    )

    assert context.prime_b64
    assert context.generator_b64

    password_hash = context.get_common_password_hash(static_salt)
    assert to_hex_u(password_hash) == '94B7555AABE9127CC58CCF4993DB6CF84D16C124'

    password_verifier = context.get_common_password_verifier(password_hash)
    assert to_hex_u(password_verifier) == (
        '7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D8129BADA1F1822223CA1A605B530E379BA4729FDC59'
        'F105B4787E5186F5C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5EA53D15C1AFF87B2B9DA6E04'
        'E058AD51CC72BFC9033B564E26480D78E955A5E29E7AB245DB2BE315E2099AFB')

    client_public = context.get_client_public(static_client_private)
    assert to_hex_u(client_public) == (
        '61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC44352E8903211C04692272D8B2D1A5358A2CF1B6E'
        '0BFCF99F921530EC8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44BE087EF06530E69F66615261'
        'EEF54073CA11CF5858F0EDFDFE15EFEAB349EF5D76988A3672FAC47B0769447B')

    server_public = context.get_server_public(password_verifier, static_server_private)
    assert to_hex_u(server_public) == (
        'BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9'
        'B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A'
        '00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58')

    common_secret = context.get_common_secret(server_public, client_public)
    assert to_hex_u(common_secret) == 'CE38B9593487DA98554ED47D70A7AE5F462EF019'

    expected_premaster_secret = (
        'B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F'
        '0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB3394'
        '3CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A')

    expected_session_key = '17EEFA1CEFC5C2E626E21598987F31E0F1B11BB'

    server_premaster_secret = context.get_server_premaster_secret(
        password_verifier, static_server_private, client_public, common_secret)
    assert to_hex_u(server_premaster_secret) == expected_premaster_secret

    client_premaster_secret = context.get_client_premaster_secret(
        password_hash, server_public, static_client_private, common_secret)
    assert to_hex_u(client_premaster_secret) == expected_premaster_secret

    server_session_key = context.get_common_session_key(server_premaster_secret)
    assert to_hex_u(server_session_key) == expected_session_key

    client_session_key = context.get_common_session_key(client_premaster_secret)
    assert to_hex_u(client_session_key) == expected_session_key

    client_session_key_prove = context.get_common_session_key_proof(
        client_session_key, static_salt, server_public, client_public)
    assert to_hex_u(client_session_key_prove) == '3F3BC67169EA71302599CF1B0F5D408B7B65D347'

    server_session_key_prove = context.get_common_session_key_proof_hash(
        server_session_key, client_session_key_prove, client_public)
    assert to_hex_u(server_session_key_prove) == '9CAB3C575A11DE37D3AC1421A9F009236A48EB55'


def test_context_raises():
    context = SRPContext('alice')

    with pytest.raises(SRPException):
        context.get_common_password_hash(123)
