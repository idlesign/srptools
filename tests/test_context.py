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

    expected_session_key = b'017EEFA1CEFC5C2E626E21598987F31E0F1B11BB'

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
    assert to_hex_u(client_session_key_prove) == b'3F3BC67169EA71302599CF1B0F5D408B7B65D347'

    server_session_key_prove = context.get_common_session_key_proof_hash(
        server_session_key, client_session_key_prove, client_public)
    assert to_hex_u(server_session_key_prove) == b'9CAB3C575A11DE37D3AC1421A9F009236A48EB55'


def test_context_raises():
    context = SRPContext('alice')

    with pytest.raises(SRPException):
        context.get_common_password_hash(123)


def test_byte_hashes():
    static_salt = int_from_hex('99e50c9ad1bd2856')
    static_client_private = int_from_hex('2b557313c052bb0e24a3c7462e8f436769a54e8d325da794004cefab83ac8b71')
    static_server_private = int_from_hex(
        '57e997761d2aeb4c8dbfed9fde120c0ec730af1237e296f58649a6b3193ff21b36f5cfaed3049ee0051e5378f666f13d'
        '0c7c91040940a77a3ff1a461666c41e9aca3bd4747d74036e34941578553eb56d369638f796707425d0294809e81363f'
        'ac90af29c7fde1ae142f8c280e3c2e17f9c4d68f644de5406aac7d378b812a34')

    context = SRPContext('bouke', 'test')

    password_hash = context.get_common_password_hash(static_salt)
    password_verifier = context.get_common_password_verifier(password_hash)
    assert hex_from(password_verifier) == (
        '52e3ee0cde007d2e7cee87acca1c041999b528e56dec925112d30a63d8e814231c2cd3bac9ae40220c44d63029912f1f'
        '7dda878e938ab5bfe7b87b854bb8385020d765054d07424eb5749fcd90344dbc0372432f6db25ae12cca4584ea72270c'
        'a61d831540b10919a31fde1b7b9e1cc7110429d8bbde1a6fe005896697b91436')

    client_public = context.get_client_public(static_client_private)
    assert hex_from(client_public) == (
        'e18b11cddbfa709020fa2c67344a20e6704dba3e5ca6c4ca864b94ff5442965c80dfa751a9404feb2234fcd02d7f179d'
        'ca4e308d76af173ec4eacc13a8daf0237bf19d4ac0ae9a4db885fdb46d5107caea8f71a8db39eda96d594e216c632a0d'
        '9720d84e8abb82b3dfa67fad099e1c67b13081bb564b2369c6db5f10358680b2')

    server_public = context.get_server_public(password_verifier, static_server_private)
    assert hex_from(server_public) == (
        '0b3cc73f40a5fbdee992995dc26bfc43558803689798731fd303cdf18fdecbb5544f5caf960910f1b9449c772032be38'
        '2b22d8763104781793553977bfdbd7cd3b05af0bf00deee22d76b477275e3294713711e3fe97f34724f9580bf2c055e7'
        '8ae138664dfecaa2fe353768e30c3cc395541a929dc2af6a66e118ca937cffe8')

    common_secret = context.get_common_secret(server_public, client_public)
    assert hex_from(common_secret) == 'cb709a3c8a6767fda651ad6543436e4da2c85268'

    expected_premaster_secret = (
        '8c0ade0a5cc22507230bf092348a518fe9c29f1cbeb7a1a089ac070da5f5f7d540377fa30703164823017f421cc71237'
        '2cc2093228fc6b05a4c77f05216c7c911fbdc2ed63f48a1ecec9da8a1edda3c810c724d8c45f83acd48a6c05f33d36b4'
        '0ebca6db6f34a3f8e69289f7e49ef3492265d18488d447fb232b56306cb39a3a')

    server_premaster_secret = context.get_server_premaster_secret(
        password_verifier, static_server_private, client_public, common_secret)
    assert hex_from(server_premaster_secret) == expected_premaster_secret

    client_premaster_secret = context.get_client_premaster_secret(
        password_hash, server_public, static_client_private, common_secret)
    assert hex_from(client_premaster_secret) == expected_premaster_secret

    expected_session_key = b'86a5aff58ae7eca772b05bbb629f5b1c51677b14'

    server_session_key = context.get_common_session_key(server_premaster_secret)
    assert hex_from(server_session_key) == expected_session_key

    client_session_key = context.get_common_session_key(client_premaster_secret)
    assert hex_from(client_session_key) == expected_session_key

    client_session_key_prove = context.get_common_session_key_proof(
        client_session_key, static_salt, server_public, client_public)
    assert hex_from(client_session_key_prove) == b'001961fb3aa5c24c437df55a18a41cabce3d57b4'

    server_session_key_prove = context.get_common_session_key_proof_hash(
        server_session_key, client_session_key_prove, client_public)
    assert hex_from(server_session_key_prove) == b'f0a6d49e5037f34b770a8e2de9ec5e3c0880953b'
