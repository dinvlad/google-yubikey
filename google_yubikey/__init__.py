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
import json
from time import time
from typing import List
from getpass import getpass
import warnings

import requests
from cryptography.hazmat.primitives import serialization
from googleapiclient.discovery import build as google_api
from ykman.descriptor import open_device
from ykman.piv import ALGO, DEFAULT_MANAGEMENT_KEY, SLOT, PivController as YubiKey

KEY_ALG = ALGO.RSA2048
GOOGLE_OAUTH2_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'


class StrEnum(Enum):
    """ Enum with string values """

    def __str__(self):
        return self.value


class Command(StrEnum):
    """ Command type """
    PRIVATE_KEY = 'private-key'
    PUBLIC_KEY = 'public-key'
    TOKEN = 'token'


class Slot(StrEnum):
    """ YubiKey slot type """
    AUTHENTICATION = f'{SLOT.AUTHENTICATION:x}'
    SIGNATURE = f'{SLOT.SIGNATURE:x}'
    KEY_MANAGEMENT = f'{SLOT.KEY_MANAGEMENT:x}'
    CARD_MANAGEMENT = f'{SLOT.CARD_MANAGEMENT:x}'
    CARD_AUTH = f'{SLOT.CARD_AUTH:x}'


class TokenType(StrEnum):
    """ Google token type """
    ID = 'id'
    ACCESS = 'access'


def parse_args():
    """ Parses command-line args """

    # top-level args
    parser = argparse.ArgumentParser(
        description='Generate a Google Service Account token with YubiKey',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        '-k', '--key-slot', dest='slot', type=Slot, choices=list(Slot),
        help='YubiKey slot', default=Slot.AUTHENTICATION,
    )
    parser.add_argument(
        '-m', '--management-key',
        help='YubiKey management key', default=DEFAULT_MANAGEMENT_KEY.hex(),
    )
    subparsers = parser.add_subparsers(
        dest='command', required=True,
        help='Command',
    )

    # "private-key" command
    parser_private_key = subparsers.add_parser(
        str(Command.PRIVATE_KEY),
        help='Generate private key on the YubiKey '
        '(can be used for many Service Accounts)',
    )
    parser_private_key.add_argument(
        '-c', '--common-name',
        help='Certificate common name', default='yubikey',
    )
    parser_private_key.add_argument(
        '-d', '--validity-days', dest='validity_days', type=int,
        help='Certificate validity, in days', default=365,
    )

    # "public-key" command
    parser_public_key = subparsers.add_parser(
        str(Command.PUBLIC_KEY),
        help='Register public key of the YubiKey with a Service Account',
    )
    parser_public_key.add_argument(
        '-a', '--service-account-email', required=True,
        help='Service Account email',
    )

    # "token" command
    parser_token = subparsers.add_parser(
        str(Command.TOKEN),
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

    args = parser.parse_args()
    setattr(args, 'slot', int(str(args.slot), 16))
    setattr(args, 'management_key', a2b_hex(args.management_key))
    setattr(args, 'pin', getpass('YubiKey PIN: '))
    return args


def get_yubikey(management_key: bytes, pin: int):
    """ Sets up YubiKey communication """
    dev = open_device()
    yubikey = YubiKey(dev.driver)
    yubikey.authenticate(management_key)
    yubikey.verify(pin)
    return yubikey


def gen_private_key(yubikey: YubiKey, slot: int, common_name: str, validity_days: int):
    """ Generates Google Service Account private key on the YubiKey """
    print('Generating private key ...')
    start = datetime.now()
    end = start + timedelta(days=validity_days)
    key = yubikey.generate_key(slot, KEY_ALG)
    yubikey.generate_self_signed_certificate(
        slot, key, common_name, start, end,
    )


def get_public_key(yubikey: YubiKey, slot: int):
    cert = yubikey.read_certificate(slot)
    return cert.public_bytes(serialization.Encoding.PEM)


def upload_pubkey(service_account_email: str, public_key: bytes):
    """ RegistersGoogle Service Account public key """
    print('Uploading public key ...')
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


def get_id_token(yubikey: YubiKey, slot: int, service_account_email: str,
                 scopes: List[str], token_lifetime: int):
    """ Generates a Google ID token with a YubiKey """
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

    sig = yubikey.sign(slot, KEY_ALG, msg.encode('utf-8'))
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
    yubikey = get_yubikey(args.management_key, args.pin)

    if args.command == str(Command.PRIVATE_KEY):
        gen_private_key(yubikey, args.slot,
                        args.common_name, args.validity_days)
    elif args.command == str(Command.PUBLIC_KEY):
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
