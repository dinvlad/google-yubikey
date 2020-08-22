"""
Emulates a GCE instance metadata server
to seamlessly generate Service Account credentials
for existing applications with a YubiKey.

It must be called with superuser privileges,
to be allowed to set up the link-local IP alias
for the instance metadata server, and
to serve its endpoint on port 80 (the privileges
are dropped for the actual request handlers, however).
"""

from abc import ABCMeta, abstractmethod
import atexit
import logging
import platform
from subprocess import PIPE, run
import sys
from typing import Type

from flask import Flask, Response, abort, redirect, request, url_for
from python_hosts import Hosts, HostsEntry
from werkzeug.exceptions import HTTPException
from ykman.piv import SLOT

from google_yubikey.device import \
    get_access_token, get_id_token, get_yubikey, \
    DEFAULT_SCOPES
from google_yubikey.util import CachedItem


class GCEMetadata:
    """ Interface for setting up GCE Metadata server in OS-specific way """
    __metaclass__ = ABCMeta

    HOSTS = ['metadata', 'metadata.google.internal']
    IP = '169.254.169.254'

    def __init__(self, slot: SLOT, prompt_management_key: bool,
                 numeric_project_id: int, service_account_email: str,
                 token_lifetime: int, cache_lifetime: int, verbosity: str):
        self.slot = slot
        self.prompt_management_key = prompt_management_key
        self.numeric_project_id = numeric_project_id
        self.service_account_email = service_account_email
        self.token_lifetime = token_lifetime
        self.cache_lifetime = cache_lifetime
        self.verbosity = verbosity

        self.add_ip()
        atexit.register(self.delete_ip)

        self.add_host()
        atexit.register(self.delete_host)

    @abstractmethod
    def add_ip(self):
        """ Add the server IP alias """
        raise NotImplementedError

    @abstractmethod
    def delete_ip(self):
        """ Delete the server IP alias """
        raise NotImplementedError

    @staticmethod
    def add_host():
        """ Add hosts entry for the server IP """
        hosts = Hosts()
        hosts.add([
            HostsEntry(
                entry_type='ipv4',
                address=GCEMetadata.IP,
                names=GCEMetadata.HOSTS,
            ),
        ])
        hosts.write()

    @staticmethod
    def delete_host():
        """ Delete hosts entry for the server IP """
        hosts = Hosts()
        hosts.remove_all_matching(GCEMetadata.IP)
        hosts.write()

    def run(self):
        """ Runs the server """
        is_debug = getattr(logging, self.verbosity) <= logging.DEBUG
        stderr = sys.stderr if is_debug else PIPE
        server = run([
            'uwsgi',
            '--http', '=0',
            '--shared-socket', GCEMetadata.IP + ':80',
            '--uid', 'nobody', '--gid', 'nobody',
            '--wsgi', 'google_yubikey.metadata:create_uwsgi_app()',
            '--set', f'slot={self.slot.value}',
            '--set', f'prompt_management_key={self.prompt_management_key}',
            '--set', f'numeric_project_id={self.numeric_project_id}',
            '--set', f'service_account_email={self.service_account_email}',
            '--set', f'token_lifetime={self.token_lifetime}',
            '--set', f'cache_lifetime={self.cache_lifetime}',
            '--set', f'verbosity={self.verbosity}',
            '--processes', '1',
            '--honour-stdin',
        ], stdout=sys.stdout, stderr=stderr, text=True, check=False)

        if not is_debug and server.returncode != 0:
            print(server.stderr)


class GCEMetadataLinux(GCEMetadata):
    """ Implements GCEMetadata for Linux """

    _INTERFACE = 'lo:0'

    def add_ip(self):
        run(
            ['ifconfig', self._INTERFACE, GCEMetadata.IP],
            stderr=sys.stderr, check=True,
        )

    def delete_ip(self):
        run(
            ['ifconfig', self._INTERFACE, 'down'],
            stderr=sys.stderr, check=True,
        )


class GCEMetadataMacOS(GCEMetadata):
    """ Implements GCEMetadata for macOS """

    _INTERFACE = 'lo0'

    def add_ip(self):
        run(
            ['ifconfig', self._INTERFACE, 'alias', GCEMetadata.IP],
            stderr=sys.stderr, check=True,
        )

    def delete_ip(self):
        run(
            ['ifconfig', self._INTERFACE, '-alias', GCEMetadata.IP],
            stderr=sys.stderr, check=True,
        )


def get_gce_metadata(slot: SLOT, prompt_management_key: bool,
                     numeric_project_id: int, service_account_email: str,
                     token_lifetime: int, cache_lifetime: int,
                     verbosity: str) -> GCEMetadata:
    """ Returns GCEMetadata instance for your OS """
    os_name = platform.system()
    metadata_type: Type[GCEMetadata]
    if os_name == 'Linux':
        metadata_type = GCEMetadataLinux
    elif os_name == 'Darwin':
        metadata_type = GCEMetadataMacOS
    else:
        raise NotImplementedError('Sorry, your OS is not supported yet')
    return metadata_type(
        slot, prompt_management_key, numeric_project_id,
        service_account_email, token_lifetime, cache_lifetime, verbosity,
    )


class UWSGIOpts:
    """ Parses options passed through uWSGI """

    def __init__(self):
        from uwsgi import opt  # pylint: disable=import-error,import-outside-toplevel

        self._opt = opt
        self.slot = int(self._get('slot'))
        self.prompt_management_key = \
            self._get('prompt_management_key') == 'True'
        self.service_account_email = self._get('service_account_email')
        self.numeric_project_id = self._get('numeric_project_id')
        self.project_id = self.service_account_email \
            .split('@')[1].split('.')[0]
        self.token_lifetime = int(self._get('token_lifetime'))
        self.cache_lifetime = int(self._get('cache_lifetime'))
        self.verbosity = self._get('verbosity')

    def _get(self, name: str):
        return self._opt[name].decode('utf-8')


def _get_log(name: str, level: str):
    """ Sets up a logger """
    log = logging.getLogger(name)
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter(
        '[%(levelname)s][%(asctime)s][%(name)s]: %(message)s',
    ))
    log.addHandler(log_handler)
    log.setLevel(level)
    return log


_CACHED_TOKEN = CachedItem()
_CACHED_IDENTITY = CachedItem()

_PROJECT_ROOT = '/computeMetadata/v1/project'
_SA_ROOT = '/computeMetadata/v1/instance/service-accounts'


def create_uwsgi_app():
    """ Sets up uWSGI app for GCE metadata server """
    opts = UWSGIOpts()
    log = _get_log('gce_metadata', opts.verbosity)
    yubikey = get_yubikey()
    app = Flask(__name__)

    @app.before_request
    def _check_request_headers():
        log.debug(request.method + ' ' + request.path)
        if request.path == '/':
            return None
        headers = request.headers
        if headers.get('X-Forwarded-For') or \
                headers.get('Metadata-Flavor') != 'Google' or \
                headers.get('Host') not in GCEMetadata.HOSTS + [GCEMetadata.IP]:
            return abort(401)
        return None

    @app.after_request
    def _add_response_headers(response: Response):
        headers = response.headers
        headers.set('Server', 'Metadata Server for VM')
        headers.set('Metadata-Flavor', 'Google')
        headers.set('X-XSS-Protection', '1')
        headers.set('X-Frame-Options', 'SAMEORIGIN')
        if response.mimetype == 'text/html':
            headers.set('Content-Type', 'application/text')
        return response

    @app.errorhandler(Exception)
    def _log_error(error: Exception):
        log.error(error)
        if isinstance(error, HTTPException):
            return error.description, error.code
        msg = error
        if len(error.args) > 0:
            msg = error.args[0]
        if msg == 'Incorrect PIN':
            return msg, 401
        return msg, 500

    @app.route('/')
    def _get_root():
        return 'computeMetadata/'

    @app.route(_PROJECT_ROOT + '/project-id')
    def _get_project_id():
        return opts.project_id

    @app.route(_PROJECT_ROOT + '/numeric-project-id')
    def _get_numeric_project_id():
        return opts.numeric_project_id

    @app.route(_SA_ROOT)
    def _get_service_accounts():
        return redirect(url_for('_get_service_accounts_root'), 301)

    @app.route(_SA_ROOT + '/')
    def _get_service_accounts_root():
        return '/\n'.join([
            'default',
            opts.service_account_email,
            '',
        ])

    @app.route(_SA_ROOT + f'/{opts.service_account_email}/')
    @app.route(_SA_ROOT + '/default/')
    def _get_sa_index():
        return {
            'aliases': 'default',
            'email': opts.service_account_email,
            'scopes': DEFAULT_SCOPES,
        }

    @app.route(_SA_ROOT + f'/{opts.service_account_email}/aliases')
    @app.route(_SA_ROOT + '/default/aliases')
    def _get_aliases():
        return 'default'

    @app.route(_SA_ROOT + f'/{opts.service_account_email}/email')
    @app.route(_SA_ROOT + '/default/email')
    def _get_email():
        return opts.service_account_email

    @app.route(_SA_ROOT + f'/{opts.service_account_email}/identity')
    @app.route(_SA_ROOT + '/default/identity')
    def _get_id_token():
        global _CACHED_IDENTITY  # pylint: disable=global-statement

        audience = request.args.get('audience')
        if not audience:
            abort(400, 'non-empty audience parameter required')
        if not _CACHED_IDENTITY.expired(audience):
            return _CACHED_IDENTITY.value
        response = get_id_token(
            yubikey, opts.slot, opts.prompt_management_key,
            opts.service_account_email, audience,
            opts.token_lifetime, opts.cache_lifetime, sys.stdout,
        )
        _CACHED_IDENTITY = CachedItem(audience, response, opts.cache_lifetime)
        return response

    @app.route(_SA_ROOT + f'/{opts.service_account_email}/scopes')
    @app.route(_SA_ROOT + '/default/scopes')
    def _get_scopes():
        return '\n'.join(DEFAULT_SCOPES + [''])

    @app.route(_SA_ROOT + f'/{opts.service_account_email}/token')
    @app.route(_SA_ROOT + '/default/token')
    def _get_access_token():
        global _CACHED_TOKEN  # pylint: disable=global-statement

        scopes = request.args.get('scopes')
        if scopes:
            scopes = scopes.split(',')
        else:
            scopes = DEFAULT_SCOPES
        if not _CACHED_TOKEN.expired(scopes):
            return _CACHED_TOKEN.value

        response = get_access_token(
            yubikey, opts.slot, opts.prompt_management_key,
            opts.service_account_email, scopes,
            opts.token_lifetime, opts.cache_lifetime, sys.stdout,
        )
        _CACHED_TOKEN = CachedItem(scopes, response, opts.cache_lifetime)
        return response

    return app
