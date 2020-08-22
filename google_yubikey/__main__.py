#!/usr/bin/env python3
"""
Command-line interface to set up and use a YubiKey
as a Google Service Account key.
"""

import argparse
from enum import Enum
import logging

from ykman.piv import PIN_POLICY, TOUCH_POLICY, SLOT

from google_yubikey.device import \
    get_yubikey, gen_private_key, get_access_token, get_id_token,\
    DEFAULT_LIFETIME, DEFAULT_SCOPES
from google_yubikey.metadata import get_gce_metadata
from google_yubikey.util import CachedItem


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
            except KeyError as error:
                raise ValueError() from error
        return convert


class Action(ArgEnum):
    """ Action type """
    GENERATE_KEY = 1
    TOKEN = 2
    SERVE = 3


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


class Verbosity(ArgEnum):
    """ Google token type """
    CRITICAL = logging.CRITICAL
    ERROR = logging.ERROR
    WARNING = logging.WARNING
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    NONE = logging.NOTSET


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
        help='YubiKey PIN policy', default=PinPolicy.DEFAULT, choices=list(PinPolicy),
    )
    parser_generate_key.add_argument(
        '-t', '--touch-policy', type=TouchPolicy.from_str(TouchPolicy),
        help='YubiKey touch policy', default=TouchPolicy.DEFAULT, choices=list(TouchPolicy),
    )
    parser_generate_key.add_argument(
        '-m', '--prompt-management-key', action='store_true',
        help='Prompt for management key',
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
        '-t', '--token-type', type=TokenType.from_str(TokenType), choices=list(TokenType),
        help='Token type', default=TokenType.ACCESS,
    )
    parser_token.add_argument(
        '-d', '--audience',
        help='Audience for ID token',
    )
    parser_token.add_argument(
        '-s', '--scopes', nargs='*', default=DEFAULT_SCOPES,
        help='Google Cloud access token scope(s)',
    )
    parser_token.add_argument(
        '-l', '--token-lifetime', type=int, default=DEFAULT_LIFETIME,
        help='Token lifetime, in seconds',
    )
    parser_token.add_argument(
        '-m', '--prompt-management-key', action='store_true',
        help='Prompt for management key',
    )

    # "serve" action
    parser_serve = subparsers.add_parser(
        str(Action.SERVE),
        help='Start a server that provides application default credentials',
    )
    parser_serve.add_argument(
        '-n', '--numeric-project-id', type=int, required=True,
        help='Google Cloud numeric project id',
    )
    parser_serve.add_argument(
        '-a', '--service-account-email', required=True,
        help='Service Account email',
    )
    parser_serve.add_argument(
        '-l', '--token-lifetime', type=int, default=DEFAULT_LIFETIME,
        help='Token lifetime, in seconds',
    )
    parser_serve.add_argument(
        '-c', '--cache-lifetime', type=int, default=CachedItem.DEFAULT_LIFETIME_SEC,
        help='Token/PIN cache lifetime, in seconds',
    )
    parser_serve.add_argument(
        '-m', '--prompt-management-key', action='store_true',
        help='Prompt for management key',
    )
    parser_serve.add_argument(
        '-v', '--verbosity', type=Verbosity.from_str(Verbosity), choices=list(Verbosity),
        help='Log verbosity level', default=Verbosity.INFO,
    )

    return parser.parse_args()


def main():
    """ Main entrypoint """
    args = parse_args()

    if args.action == str(Action.GENERATE_KEY):
        public_key = gen_private_key(
            get_yubikey(), args.slot, args.prompt_management_key,
            args.pin_policy, args.touch_policy,
            args.subject, args.valid_days,
        )
        print(public_key.decode('utf-8'))
    elif args.action == str(Action.TOKEN):
        if args.token_type == TokenType.ACCESS:
            print(get_access_token(
                get_yubikey(), args.slot.value, args.prompt_management_key,
                args.service_account_email, args.scopes, args.token_lifetime,
            )['access_token'])
        else:
            print(get_id_token(
                get_yubikey(), args.slot.value, args.prompt_management_key,
                args.service_account_email, args.audience, args.token_lifetime,
            ))
    elif args.action == str(Action.SERVE):
        get_gce_metadata(
            args.slot, args.prompt_management_key, args.numeric_project_id,
            args.service_account_email, args.token_lifetime, args.cache_lifetime,
            args.verbosity.name,
        ).run()


if __name__ == "__main__":
    main()
