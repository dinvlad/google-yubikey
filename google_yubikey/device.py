"""
Exposes various high-level operations for the YubiKey.
"""

from base64 import b64encode
from datetime import datetime, timedelta
from getpass import getpass
import json
import sys
from time import time
from typing import List

import requests
from cryptography.hazmat.primitives import serialization
from ykman.descriptor import open_device
from ykman.cli.util import prompt_for_touch
from ykman.piv import \
    ALGO, DEFAULT_MANAGEMENT_KEY, \
    PIN_POLICY, TOUCH_POLICY, SLOT, PivController as YubiKey

from google_yubikey.util import CachedItem

_KEY_ALG = ALGO.RSA2048
_GOOGLE_OAUTH2_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
DEFAULT_SCOPES = ['https://www.googleapis.com/auth/cloud-platform']
DEFAULT_LIFETIME = 3600


def _log(message: str, file=sys.stderr):
    """ Print information for the user """
    print(message, file=file)


def get_yubikey(stream=sys.stderr):
    """ Sets up YubiKey communication """
    _log('Connecting to the YubiKey...', stream)
    dev = open_device()
    yubikey = YubiKey(dev.driver)
    _log('Connected', stream)
    return yubikey


_CACHED_PIN = CachedItem()
_CACHED_MGMT_KEY = CachedItem()


def authenticate(yubikey: YubiKey, prompt_management_key: bool,
                 cache_lifetime=CachedItem.DEFAULT_LIFETIME_SEC, stream=sys.stderr):
    """ Authenticates user to the YubiKey """
    global _CACHED_PIN, _CACHED_MGMT_KEY  # pylint: disable=global-statement

    _log('Authenticating to the YubiKey...', stream)

    pin = _CACHED_PIN.value
    if _CACHED_PIN.expired():
        pin = getpass('Enter PIN: ', stream)
        _CACHED_PIN = CachedItem(None, pin, cache_lifetime)
    yubikey.verify(pin, touch_callback=prompt_for_touch)

    mgmt_key = _CACHED_MGMT_KEY.value
    if not prompt_management_key:
        mgmt_key = DEFAULT_MANAGEMENT_KEY
    elif _CACHED_MGMT_KEY.expired():
        mgmt_key = getpass('Enter management key: ', stream)
        _CACHED_MGMT_KEY = CachedItem(None, mgmt_key, cache_lifetime)
    yubikey.authenticate(mgmt_key, touch_callback=prompt_for_touch)

    _log('Authenticated', stream)


def gen_private_key(yubikey: YubiKey, slot: SLOT, prompt_management_key: bool,
                    pin_policy: PIN_POLICY, touch_policy: TOUCH_POLICY,
                    subject: str, valid_days: int):
    """ Generates a private key and certificate on the YubiKey """
    authenticate(yubikey, prompt_management_key)

    _log('Generating private key on YubiKey...')
    public_key = yubikey.generate_key(
        slot.value, _KEY_ALG, pin_policy.value, touch_policy.value,
    )

    _log('Generating certificate on YubiKey...')
    start = datetime.now()
    end = start + timedelta(days=valid_days)
    yubikey.generate_self_signed_certificate(
        slot.value, public_key, subject, start, end,
        touch_callback=prompt_for_touch,
    )
    return get_public_key(yubikey, slot)


def get_public_key(yubikey: YubiKey, slot: SLOT):
    """ Reads public key from YubiKey """
    cert = yubikey.read_certificate(slot.value)
    return cert.public_bytes(serialization.Encoding.PEM)


def _b64encode_str(bbytes: bytes):
    """ Encodes bytes as base64 string """
    return b64encode(bbytes).decode('utf-8')


def _json_b64encode(obj: dict):
    """ Converts a dict to a base64-encoded JSON string """
    json_str = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    return _b64encode_str(json_str)


def _get_jwt(yubikey: YubiKey, slot: int, prompt_management_key: bool,
             service_account_email: str, audience: str, scopes: List[str],
             token_lifetime: int, cache_lifetime: int, stream=sys.stderr):
    """ Generates a general-purpose Google JWT with a YubiKey """
    authenticate(yubikey, prompt_management_key, cache_lifetime, stream)

    iat = time()
    header = {
        'typ': 'JWT',
        'alg': 'RS256',
    }
    payload = {
        'iss': service_account_email,
        'aud': audience,
        'iat': iat,
        'exp': iat + token_lifetime,
    }
    if scopes:
        payload['scope'] = ' '.join(scopes)

    msg = f'{_json_b64encode(header)}.{_json_b64encode(payload)}'
    sig = yubikey.sign(slot, _KEY_ALG, msg.encode('utf-8'))
    sig = _b64encode_str(sig)

    return f'{msg}.{sig}'


def get_id_token(yubikey: YubiKey, slot: int, prompt_management_key: bool,
                 service_account_email: str, audience: str, token_lifetime: int,
                 cache_lifetime=CachedItem.DEFAULT_LIFETIME_SEC, stream=sys.stderr):
    """ Generates a Google ID token with a YubiKey """
    if not audience:
        raise ValueError('ID tokens must use a non-empty audience')
    return _get_jwt(
        yubikey, slot, prompt_management_key,
        service_account_email, audience, [],
        token_lifetime, cache_lifetime, stream,
    )


def get_access_token(yubikey: YubiKey, slot: int, prompt_management_key: bool,
                     service_account_email: str, scopes: List[str], token_lifetime: int,
                     cache_lifetime=CachedItem.DEFAULT_LIFETIME_SEC, stream=sys.stderr):
    """ Generates a Google Access token with a YubiKey """
    assertion = _get_jwt(
        yubikey, slot, prompt_management_key,
        service_account_email, _GOOGLE_OAUTH2_TOKEN_ENDPOINT, scopes,
        token_lifetime, cache_lifetime, stream,
    )
    response = requests.post(
        url=_GOOGLE_OAUTH2_TOKEN_ENDPOINT,
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': assertion,
        },
    )
    if not response.ok:
        raise RuntimeError(response.json()['error_description'])

    return response.json()
