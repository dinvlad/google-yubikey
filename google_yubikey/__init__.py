#!/usr/bin/env python3
"""
This module allows one to use a YubiKey
to generate Google Service Account tokens.
"""

import argparse
from base64 import b64encode
from binascii import a2b_hex
from datetime import datetime, timedelta
from enum import Enum
from getpass import getpass
from io import BytesIO
import json
from time import time
from typing import List, Optional
import warnings

import requests
from click import Context, Command
from cryptography.hazmat.primitives import serialization
from googleapiclient.discovery import build as google_api
from ykman.descriptor import open_device
from ykman.cli.util import prompt_for_touch
from ykman.piv import \
    ALGO, DEFAULT_MANAGEMENT_KEY, \
    PIN_POLICY, TOUCH_POLICY, SLOT, PivController as YubiKey

KEY_ALG = ALGO.RSA2048
GOOGLE_OAUTH2_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'


class ArgEnum(Enum):
    """ Enum for command-line argument choices """

    def __str__(self):
        return str(self.name).lower().replace('_', '-')

    @staticmethod
    def from_str(clazz):
        """ Converts value from string """
        def convert(str_value: str):
            try:
                return clazz[str_value.upper().replace('-', '_')]
            except KeyError:
                raise ValueError()
        return convert


class Action(ArgEnum):
    """ Action type """
    GENERATE_KEY = 1
    UPLOAD_KEY = 2
    TOKEN = 3


class Slot(ArgEnum):
    """ YubiKey slot type """
    AUTHENTICATION = SLOT.AUTHENTICATION.value
    CARD_MANAGEMENT = SLOT.CARD_MANAGEMENT.value
    SIGNATURE = SLOT.SIGNATURE.value
    KEY_MANAGEMENT = SLOT.KEY_MANAGEMENT.value
    CARD_AUTH = SLOT.CARD_AUTH.value
    ATTESTATION = SLOT.ATTESTATION.value


class PinPolicy(ArgEnum):
    """ YubiKey pin policy """
    DEFAULT = PIN_POLICY.DEFAULT.value
    NEVER = PIN_POLICY.NEVER.value
    ONCE = PIN_POLICY.ONCE.value
    ALWAYS = PIN_POLICY.ALWAYS.value


class TouchPolicy(ArgEnum):
    """ YubiKey touch policy """
    DEFAULT = TOUCH_POLICY.DEFAULT.value
    NEVER = TOUCH_POLICY.NEVER.value
    ALWAYS = TOUCH_POLICY.ALWAYS.value
    CACHED = TOUCH_POLICY.CACHED.value


class TokenType(ArgEnum):
    """ Google token type """
    ID = 1
    ACCESS = 2


def parse_args():
    """ Parses command-line args """

    # top-level args
    parser = argparse.ArgumentParser(
        description='Generate a Google Service Account token with YubiKey',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '-k', '--key-slot', dest='slot', type=Slot.from_str(Slot),
        help='YubiKey slot', default=Slot.AUTHENTICATION, choices=list(Slot),
    )
    subparsers = parser.add_subparsers(
        dest='action', required=True,
        help='Action',
    )

    # "generate-key" action
    parser_generate_key = subparsers.add_parser(
        str(Action.GENERATE_KEY),
        help='Generate private key on the YubiKey '
        '(can be used for many Service Accounts)',
    )
    parser_generate_key.add_argument(
        '-s', '--subject',
        help='Subject common name (CN) for the key', default='yubikey',
    )
    parser_generate_key.add_argument(
        '-d', '--valid-days', type=int,
        help='Number of days until the key expires', default=365,
    )
    parser_generate_key.add_argument(
        '-p', '--pin-policy', type=PinPolicy.from_str(PinPolicy),
        help='YubiKey PIN policy', default=PinPolicy.ONCE, choices=list(PinPolicy),
    )
    parser_generate_key.add_argument(
        '-t', '--touch-policy', type=TouchPolicy.from_str(TouchPolicy),
        help='YubiKey touch policy', default=TouchPolicy.ALWAYS, choices=list(TouchPolicy),
    )

    # "upload-key" action
    parser_upload_key = subparsers.add_parser(
        str(Action.UPLOAD_KEY),
        help='Associate public key of the YubiKey with a Service Account',
    )
    parser_upload_key.add_argument(
        '-a', '--service-account-email', required=True,
        help='Service Account email',
    )

    # "token" action
    parser_token = subparsers.add_parser(
        str(Action.TOKEN),
        help='Generate a token',
    )
    parser_token.add_argument(
        '-a', '--service-account-email', required=True,
        help='Service Account email',
    )
    parser_token.add_argument(
        '-s', '--scopes', nargs='*', default=['cloud-platform'],
        help='Google Cloud scope(s)',
    )
    parser_token.add_argument(
        '-l', '--token-lifetime', type=int, default=3600,
        help='Token lifetime, in seconds',
    )
    parser_token.add_argument(
        '-t', '--token-type', type=TokenType, choices=list(TokenType),
        help='Token type, in seconds', default=TokenType.ACCESS,
    )

    return parser.parse_args()


def get_yubikey():
    """ Sets up YubiKey communication """
    dev = open_device()
    return YubiKey(dev.driver)


def authenticate(yubikey: YubiKey):
    """ Authenticates user to the YubiKey """
    print('Authenticating...')
    pin = getpass('Enter PIN: ')
    yubikey.verify(pin, touch_callback=prompt_for_touch)

    mgmt_key = getpass('Enter management key [blank to use default key]')
    mgmt_key = mgmt_key or DEFAULT_MANAGEMENT_KEY
    yubikey.authenticate(mgmt_key, touch_callback=prompt_for_touch)


def gen_private_key(yubikey: YubiKey, slot: SLOT,
                    pin_policy: PIN_POLICY, touch_policy: TOUCH_POLICY,
                    subject: str, valid_days: int):
    """ Generates a private key and certificate on the YubiKey """
    authenticate(yubikey)

    print('Generating private key...')
    public_key = yubikey.generate_key(
        slot.value, KEY_ALG, pin_policy.value, touch_policy.value,
    )

    print('Generating certificate...')
    start = datetime.now()
    end = start + timedelta(days=valid_days)
    yubikey.generate_self_signed_certificate(
        slot.value, public_key, subject, start, end,
        touch_callback=prompt_for_touch,
    )


def get_public_key(yubikey: YubiKey, slot: SLOT):
    """ Reads public key from YubiKey """
    cert = yubikey.read_certificate(slot.value)
    return cert.public_bytes(serialization.Encoding.PEM)


def upload_pubkey(service_account_email: str, public_key: bytes):
    """ Registers Google Service Account public key """
    print('Uploading public key...')
    warnings.filterwarnings(
        "ignore", "Your application has authenticated using end user credentials"
    )
    # pylint: disable=maybe-no-member
    response = google_api('iam', 'v1').projects().serviceAccounts().keys().upload(
        name=f'projects/-/serviceAccounts/{service_account_email}',
        body={
            'publicKeyData': b64encode_str(public_key),
        },
    ).execute()
    return response['name'].split('/')[-1]


def b64encode_str(bbytes: bytes):
    """ Encodes bytes as base64 string """
    return b64encode(bbytes).decode('utf-8')


def json_b64encode(obj: dict):
    """ Converts a dict to a base64-encoded JSON string """
    json_str = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    return b64encode_str(json_str)


def get_id_token(yubikey: YubiKey, slot: SLOT, service_account_email: str,
                 scopes: List[str], token_lifetime: int):
    """ Generates a Google ID token with a YubiKey """
    authenticate(yubikey)

    iat = time()
    header = {
        'typ': 'JWT',
        'alg': 'RS256',
    }
    payload = {
        'iss': service_account_email,
        'aud': GOOGLE_OAUTH2_TOKEN_ENDPOINT,
        'iat': iat,
        'exp': iat + token_lifetime,
        'scope': ' '.join((
            f'https://www.googleapis.com/auth/{s}' for s in scopes
        )),
    }
    msg = f'{json_b64encode(header)}.{json_b64encode(payload)}'

    sig = yubikey.sign(slot.value, KEY_ALG, msg.encode('utf-8'))
    sig = b64encode_str(sig)

    return f'{msg}.{sig}'


def get_access_token(id_token: str):
    """ Generates a Google Access token from a Google ID token """
    response = requests.post(
        url=GOOGLE_OAUTH2_TOKEN_ENDPOINT,
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': id_token,
        },
    )
    return response.json()['access_token']


def main():
    """ Main entrypoint """
    args = parse_args()
    yubikey = get_yubikey()

    if args.action == str(Action.GENERATE_KEY):
        gen_private_key(
            yubikey, args.slot,
            args.pin_policy, args.touch_policy,
            args.subject, args.valid_days,
        )
    elif args.action == str(Action.UPLOAD_KEY):
        public_key = get_public_key(yubikey, args.slot)
        key_id = upload_pubkey(args.service_account_email, public_key)
        print(f'Key id: {key_id}')
    else:
        id_token = get_id_token(
            yubikey, args.slot, args.service_account_email,
            args.scopes, args.token_lifetime,
        )
        if args.token_type == TokenType.ACCESS:
            print(get_access_token(id_token))
        else:
            print(id_token)


if __name__ == "__main__":
    main()
