#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A small mock of the CyberArk Central Credential Provider (CCP) REST API.

It implements the documented retrieve-password call used by Jumpserver:

    GET /AIMWebService/api/Accounts

Supported query parameters (names are case-insensitive):

    AppID                        application identifier (see ``--no-app-id``)
    Query                        semicolon separated criteria, for example
                                 ``Safe=Linux;Folder=Root;UserName=root``
    Safe, Folder, Object         direct criteria
    UserName, Address, Database, PolicyID, PlatformID
    Reason                       free text, kept in the request log (audit)
    FailRequestOnPasswordChange  ``true`` fails while the password is changing

When both ``Query`` and the direct criteria are supplied, ``Query`` wins.
Unknown attributes inside ``Query`` are rejected with a 400 error so that
typos in the Jumpserver query template are visible immediately.

A successful call returns HTTP 200:

    {
      "Content": "password",
      "UserName": "root",
      "Address": "10.0.0.1",
      "Database": "",
      "PasswordChangeInProcess": false
    }

Failures use the CyberArk error envelope:

    {"ErrorCode": "APPAP004E", "ErrorMsg": "..."}

``APPAP004E`` is the only code the Jumpserver client relies on: it means "the
object was not found" and makes the client fall back to the local password.
The remaining codes are mocked as constants so they can be aligned with the
CCP version that is deployed.

Run it standalone::

    python apps/accounts/mock_cyberark_ccp.py --port 8201
    python apps/accounts/mock_cyberark_ccp.py --port 8201 --data accounts.json

Then point Jumpserver at it::

    VAULT_ENABLED: true
    VAULT_BACKEND: cyberark
    VAULT_CYBERARK_API_URL: http://127.0.0.1:8201
    VAULT_CYBERARK_APP_ID: JMS
    VAULT_CYBERARK_SAFE: Linux
"""
import argparse
import json
import ssl
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

__all__ = [
    'MockAccount', 'CyberArkCCPMock', 'create_server', 'start_in_thread',
    'DEFAULT_ACCOUNTS',
]

ENDPOINT_PATH = '/AIMWebService/api/Accounts'

ERROR_OBJECT_NOT_FOUND = 'APPAP004E'
ERROR_BAD_REQUEST = 'APPAP002E'
ERROR_UNAUTHORIZED = 'APPAP006E'
ERROR_PASSWORD_CHANGE = 'APPAP306E'

# Query attribute -> MockAccount field
QUERY_ATTRIBUTES = {
    'safe': 'safe',
    'folder': 'folder',
    'object': 'object_name',
    'username': 'username',
    'address': 'address',
    'database': 'database',
    'policyid': 'policy_id',
    'platformid': 'platform_id',
}

DIRECT_PARAMETERS = (
    'safe', 'folder', 'object', 'username', 'address',
    'database', 'policyid', 'platformid',
)


@dataclass
class MockAccount:
    safe: str = ''
    object_name: str = ''
    username: str = ''
    folder: str = ''
    address: str = ''
    database: str = ''
    policy_id: str = ''
    platform_id: str = ''
    content: str = ''
    password_change_in_process: bool = False

    @classmethod
    def from_dict(cls, data):
        fields = {item.name for item in cls.__dataclass_fields__.values()}
        return cls(**{key: value for key, value in data.items() if key in fields})


DEFAULT_ACCOUNTS = [
    MockAccount(
        safe='Linux', folder='Root', object_name='root',
        username='root', address='10.0.0.1', content='root-password',
    ),
    MockAccount(
        safe='Linux', folder='Root', object_name='deploy',
        username='deploy', address='10.0.0.1', content='deploy-password',
    ),
    MockAccount(
        safe='Windows', folder='Root', object_name='svc-web',
        username='svc-web', address='10.0.0.2', content='svc-password',
        password_change_in_process=True,
    ),
]


def error_payload(code, message):
    return {'ErrorCode': code, 'ErrorMsg': message}


class CyberArkCCPMock(object):
    """In-memory implementation of the CCP retrieve-password endpoint."""

    quiet = False

    def __init__(
            self, accounts=None, app_ids=None, require_app_id=True,
            case_sensitive=False, unique_match=False
    ):
        self.accounts = list(accounts or DEFAULT_ACCOUNTS)
        self.app_ids = set(app_ids) if app_ids else None
        self.require_app_id = require_app_id
        self.case_sensitive = case_sensitive
        self.unique_match = unique_match
        self.requests = []

    # -------- request handling --------

    def handle(self, params):
        params = {str(key).lower(): str(value) for key, value in params.items()}
        app_id = params.get('appid', '')

        status, payload = self._check_app_id(app_id)
        if status != 200:
            return self._record(params, status, payload)

        criteria, error = self._build_criteria(params)
        if error:
            return self._record(params, 400, error_payload(ERROR_BAD_REQUEST, error))

        matches = [
            account for account in self.accounts
            if self._matches(account, criteria)
        ]
        if not matches:
            return self._record(params, 400, error_payload(
                ERROR_OBJECT_NOT_FOUND,
                'The object was not found for the supplied query',
            ))
        if len(matches) > 1 and self.unique_match:
            return self._record(params, 400, error_payload(
                ERROR_BAD_REQUEST,
                f'{len(matches)} objects match the query, narrow it down',
            ))

        account = matches[0]
        fail_on_change = params.get(
            'failrequestonpasswordchange', ''
        ).lower() in ('true', '1', 'yes')
        if account.password_change_in_process and fail_on_change:
            return self._record(params, 400, error_payload(
                ERROR_PASSWORD_CHANGE,
                'The password of the object is currently being changed',
            ))

        payload = {
            'Content': account.content,
            'UserName': account.username,
            'Address': account.address,
            'Database': account.database,
            'PasswordChangeInProcess': account.password_change_in_process,
        }
        return self._record(params, 200, payload)

    def _check_app_id(self, app_id):
        if not self.require_app_id:
            return 200, None
        if not app_id:
            return 401, error_payload(
                ERROR_UNAUTHORIZED, 'The AppID parameter is required'
            )
        if self.app_ids is not None and app_id not in self.app_ids:
            return 403, error_payload(
                ERROR_UNAUTHORIZED,
                f'The application "{app_id}" is not authorized',
            )
        return 200, None

    def _build_criteria(self, params):
        criteria = {}
        for name in DIRECT_PARAMETERS:
            value = params.get(name, '').strip()
            if value:
                criteria[name] = value

        query = params.get('query', '').strip()
        if not query:
            if not criteria:
                return {}, 'A Query or at least one attribute is required'
            return criteria, None

        for part in query.split(';'):
            part = part.strip()
            if not part:
                continue
            if '=' not in part:
                return {}, f'Invalid query segment: "{part}"'
            name, _, value = part.partition('=')
            name = name.strip().lower()
            if name not in QUERY_ATTRIBUTES:
                supported = ', '.join(sorted(QUERY_ATTRIBUTES))
                return {}, f'Unsupported query attribute "{name}", use: {supported}'
            criteria[name] = value.strip()
        if not criteria:
            return {}, 'The query is empty'
        return criteria, None

    def _matches(self, account, criteria):
        for name, expected in criteria.items():
            actual = getattr(account, QUERY_ATTRIBUTES[name]) or ''
            if not self._equals(actual, expected):
                return False
        return True

    def _equals(self, actual, expected):
        actual = str(actual)
        expected = str(expected)
        if self.case_sensitive:
            return actual == expected
        return actual.lower() == expected.lower()

    def _record(self, params, status, payload):
        self.requests.append({
            'app_id': params.get('appid', ''),
            'query': params.get('query', ''),
            'reason': params.get('reason', ''),
            'status': status,
            'payload': payload,
        })
        if not self.quiet:
            print(
                f'[mock-ccp] {status} appid={params.get("appid", "-") or "-"} '
                f'query={params.get("query", "-") or "-"} '
                f'reason={params.get("reason", "-") or "-"}',
                file=sys.stderr,
            )
        return status, payload


class _MockHandler(BaseHTTPRequestHandler):
    server_version = 'CyberArkCCPMock/1.0'

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path.rstrip('/') != ENDPOINT_PATH:
            self._send(404, error_payload(
                'HTTP404', f'Unknown endpoint: {parsed.path}'
            ))
            return
        params = {
            key: values[-1]
            for key, values in parse_qs(
                parsed.query, keep_blank_values=True
            ).items()
        }
        status, payload = self.server.mock.handle(params)
        self._send(status, payload)

    def do_POST(self):
        self._send(405, error_payload('HTTP405', 'Only GET is supported'))

    def _send(self, status, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        if not getattr(self.server.mock, 'quiet', False):
            sys.stderr.write('[mock-ccp] %s\n' % (fmt % args))


def create_server(mock, host='127.0.0.1', port=0, tls_cert=None, tls_key=None):
    httpd = ThreadingHTTPServer((host, port), _MockHandler)
    httpd.daemon_threads = True
    httpd.mock = mock
    if tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_cert, tls_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    return httpd


def start_in_thread(mock, host='127.0.0.1', port=0, **kwargs):
    """Start the mock and return ``(server, thread, base_url)``."""
    server = create_server(mock, host=host, port=port, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    scheme = 'https' if kwargs.get('tls_cert') else 'http'
    host, port = server.server_address[:2]
    return server, thread, f'{scheme}://{host}:{port}'


def load_accounts(path):
    with open(path, encoding='utf-8') as file:
        data = json.load(file)
    if isinstance(data, dict):
        data = data.get('accounts', [])
    return [MockAccount.from_dict(item) for item in data]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Mock of the CyberArk CCP retrieve-password API',
    )
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8201)
    parser.add_argument(
        '--data', help='JSON file with an "accounts" list',
    )
    parser.add_argument(
        '--app-id', action='append', dest='app_ids',
        help='Allowed AppID, repeatable. Defaults to any non-empty value',
    )
    parser.add_argument(
        '--no-app-id', action='store_true', help='Do not require AppID',
    )
    parser.add_argument(
        '--case-sensitive', action='store_true',
        help='Match attribute values case-sensitively',
    )
    parser.add_argument(
        '--unique-match', action='store_true',
        help='Fail when more than one object matches the query',
    )
    parser.add_argument('--tls-cert', help='PEM certificate for HTTPS')
    parser.add_argument('--tls-key', help='PEM private key for HTTPS')
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args(argv)

    accounts = load_accounts(args.data) if args.data else DEFAULT_ACCOUNTS
    mock = CyberArkCCPMock(
        accounts=accounts, app_ids=args.app_ids,
        require_app_id=not args.no_app_id,
        case_sensitive=args.case_sensitive,
        unique_match=args.unique_match,
    )
    mock.quiet = args.quiet
    server = create_server(
        mock, host=args.host, port=args.port,
        tls_cert=args.tls_cert, tls_key=args.tls_key,
    )
    scheme = 'https' if args.tls_cert else 'http'
    print(
        f'Mock CCP listening on {scheme}://{args.host}:{args.port}{ENDPOINT_PATH}',
        file=sys.stderr,
    )
    print(
        f'Accounts: {", ".join(a.object_name or "?" for a in accounts)}',
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
