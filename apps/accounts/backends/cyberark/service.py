# -*- coding: utf-8 -*-
import contextvars
import json

import requests
from requests import exceptions as request_exceptions

from common.utils import get_logger, random_string

logger = get_logger(__name__)

__all__ = [
    'CyberArkCCPError', 'CyberArkCCPClient', 'as_bool',
    'build_query', 'build_reason', 'set_ccp_reason',
]

DEFAULT_ENDPOINT_PATH = '/AIMWebService/api/Accounts'
DEFAULT_QUERY_TEMPLATE = 'Safe={safe};Folder={folder};UserName={username}'
OBJECT_NOT_FOUND_CODE = 'APPAP004E'
RESERVED_CHARS = (';', '=')
REASON_MAX_LENGTH = 900


class CyberArkCCPError(Exception):
    def __init__(self, message, status_code=None, code=''):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


_reason = contextvars.ContextVar('cyberark_ccp_reason', default='')


def set_ccp_reason(reason=''):
    """Set an explicit audit reason for the current execution context."""
    _reason.set(reason or '')


def build_reason():
    """Build the CCP `Reason` from the current request when none is set."""
    reason = _reason.get()
    if reason:
        return reason

    try:
        from jumpserver.utils import get_current_request
        request = get_current_request()
    except Exception:
        request = None

    if request is None:
        return 'JMS'

    username = getattr(getattr(request, 'user', None), 'username', '') or '-'
    path = getattr(request, 'path', '') or ''
    token_id = _get_connection_token_id(request, path)
    if token_id:
        return f'JMS-CONNECT component={username} token={token_id}'
    method = getattr(request, 'method', '') or ''
    return f'JMS {method} {path} user={username}'.strip()


def _get_connection_token_id(request, path):
    # The connect path is called by a component account, so the token id is the
    # only link back to the end user in the CyberArk audit trail.
    if 'connection-token' not in path or not path.rstrip('/').endswith('/secret'):
        return ''
    try:
        body = getattr(request, 'body', b'') or b''
        data = json.loads(body) if body else {}
    except Exception:
        return ''
    if not isinstance(data, dict):
        return ''
    return str(data.get('id') or '')


def build_query(template=DEFAULT_QUERY_TEMPLATE, **values):
    """Render the CCP query from a template.

    Empty values are dropped so that a missing folder does not send an empty
    condition. Values that could break the `key=value;key=value` syntax are
    rejected instead of being escaped, because CCP has no escaping rules.
    """
    template = (template or DEFAULT_QUERY_TEMPLATE).strip()
    cleaned = {key: str(value or '').strip() for key, value in values.items()}
    extra = cleaned.pop('extra', '')

    _validate_values(cleaned)
    try:
        query = template.format(**cleaned)
    except KeyError as error:
        raise CyberArkCCPError(
            f'Unknown placeholder in the CyberArk query template: {error}'
        ) from error
    except (IndexError, ValueError) as error:
        raise CyberArkCCPError(
            f'Invalid CyberArk query template: {error}'
        ) from error

    parts = [part.strip() for part in query.split(';')]
    parts = [part for part in parts if part and not part.endswith('=')]
    if extra:
        if ';' in extra:
            raise CyberArkCCPError(
                'Invalid CyberArk query label: it must not contain ";"'
            )
        parts.append(extra.strip())
    if not parts:
        raise CyberArkCCPError(
            'The CyberArk query is empty, please check the query template'
        )
    return ';'.join(parts)


def _validate_values(values):
    for key, value in values.items():
        if any(char in value for char in RESERVED_CHARS):
            raise CyberArkCCPError(
                f'Invalid CyberArk query value for "{key}": it must not contain '
                f'{", ".join(RESERVED_CHARS)}'
            )


class CyberArkCCPClient(object):
    def __init__(
            self, api_url='', app_id='', safe='', folder='', query_template='',
            timeout=3, verify_tls=True, cacert_file='',
            fail_on_password_change=True
    ):
        self.api_url = (api_url or '').strip().rstrip('/')
        self.app_id = (app_id or '').strip()
        self.safe = (safe or '').strip()
        self.folder = (folder or '').strip()
        self.query_template = (query_template or '').strip() or DEFAULT_QUERY_TEMPLATE
        self.timeout = int(timeout or 3)
        self.verify_tls = as_bool(verify_tls, default=True)
        self.cacert_file = (cacert_file or '').strip()
        self.fail_on_password_change = as_bool(
            fail_on_password_change, default=True
        )
        self.session = requests.Session()

    @property
    def endpoint(self):
        if not self.api_url:
            return ''
        if self.api_url.lower().endswith(DEFAULT_ENDPOINT_PATH.lower()):
            return self.api_url
        return f'{self.api_url}{DEFAULT_ENDPOINT_PATH}'

    def is_active(self):
        if not self.endpoint:
            return False, 'The CyberArk CCP API URL is not configured'
        probe = build_query(
            self.query_template, safe=self.safe, folder=self.folder,
            username=f'jumpserver-probe-{random_string(8)}',
        )
        try:
            self.fetch(probe, reason='JMS-CONNECT-TEST')
        except CyberArkCCPError as error:
            return False, f'CyberArk CCP is not reachable: {error}'
        return True, ''

    def fetch(self, query, reason='', app_id=''):
        """Return the CCP account payload; an unknown object returns {}."""
        if not self.endpoint:
            raise CyberArkCCPError('The CyberArk CCP API URL is not configured')

        params = {'Query': query}
        app_id = (app_id or self.app_id or '').strip()
        if app_id:
            params['AppID'] = app_id
        if self.fail_on_password_change:
            params['FailRequestOnPasswordChange'] = 'true'
        reason = (reason or build_reason())[:REASON_MAX_LENGTH]
        if reason:
            params['Reason'] = reason

        response = self._get(params)
        if response.status_code == 200:
            data = _normalize_response(response)
            if data.get('passwordchangeinprocess') and self.fail_on_password_change:
                raise CyberArkCCPError(
                    'The CyberArk password is being changed, please retry later'
                )
            return data

        error = _build_error(response)
        if error.status_code in (400, 404) and error.code == OBJECT_NOT_FOUND_CODE:
            return {}
        raise error

    def _get(self, params):
        try:
            return self.session.get(
                self.endpoint, params=params,
                headers={'Accept': 'application/json'},
                timeout=self.timeout,
                verify=self.cacert_file or self.verify_tls,
            )
        except request_exceptions.SSLError as error:
            raise CyberArkCCPError(
                f'TLS handshake failed, check the server certificate: {error}'
            ) from error
        except request_exceptions.RequestException as error:
            raise CyberArkCCPError(f'Request failed: {error}') from error


def _normalize_response(response):
    try:
        data = response.json()
    except ValueError as error:
        raise CyberArkCCPError('Invalid JSON response from CyberArk CCP') from error
    if not isinstance(data, dict):
        raise CyberArkCCPError('Invalid response from CyberArk CCP')
    return {str(key).lower(): value for key, value in data.items()}


def _build_error(response):
    code = ''
    message = ''
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        code = str(body.get('ErrorCode') or '')
        message = str(body.get('ErrorMsg') or '')
    if not message:
        message = (getattr(response, 'text', '') or '')[:300].strip()
    if not message:
        message = f'HTTP {response.status_code}'
    return CyberArkCCPError(
        f'{code} {message}'.strip(),
        status_code=response.status_code, code=code,
    )


def as_bool(value, default=True):
    if value is None or value == '':
        return default
    if isinstance(value, str):
        return value.strip().lower() not in ('0', 'false', 'no', 'off')
    return bool(value)
