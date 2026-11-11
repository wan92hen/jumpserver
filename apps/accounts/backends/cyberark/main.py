# -*- coding: utf-8 -*-
from jumpserver.const import CONFIG

from common.db.utils import get_logger

from .service import (
    CyberArkCCPClient, CyberArkCCPError, as_bool, build_query,
)
from ..base.vault import BaseVault
from ...const import VaultTypeChoices

# Import the canonical exception module: this backend can be loaded as
# `apps.accounts.backends.cyberark.main` while the API layer catches the
# `accounts.exceptions` classes. A relative import would create a second copy
# of those classes and break `except VaultUnavailableException`.
from accounts.exceptions import VaultException, VaultUnavailableException

logger = get_logger(__name__)

__all__ = ['Vault']


def _config(kwargs, name, default=None):
    value = kwargs.get(name)
    if value not in (None, ''):
        return value
    return getattr(CONFIG, name, default)


def _same_user(expected, actual):
    """Compare user names while ignoring the domain notation."""
    actual = str(actual or '').strip()
    if not actual:
        return True

    def normalize(value):
        value = str(value or '').strip().lower()
        return value.split('\\')[-1].split('@')[0]

    return normalize(expected) == normalize(actual)


class Vault(BaseVault):
    """CyberArk CCP is a read-only credential source.

    The local database keeps its own copy of the secret as a fallback, so the
    create/update/delete hooks must never clear it.
    """

    type = VaultTypeChoices.cyberark
    read_only = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fallback_local = as_bool(
            _config(kwargs, 'VAULT_CYBERARK_FALLBACK_LOCAL', True), default=True
        )
        self.client = CyberArkCCPClient(
            api_url=_config(kwargs, 'VAULT_CYBERARK_API_URL', ''),
            app_id=_config(kwargs, 'VAULT_CYBERARK_APP_ID', ''),
            safe=_config(kwargs, 'VAULT_CYBERARK_SAFE', ''),
            folder=_config(kwargs, 'VAULT_CYBERARK_FOLDER', ''),
            query_template=_config(kwargs, 'VAULT_CYBERARK_QUERY_TEMPLATE', ''),
            timeout=_config(kwargs, 'VAULT_CYBERARK_TIMEOUT', 3),
            verify_tls=_config(kwargs, 'VAULT_CYBERARK_VERIFY_TLS', True),
            cacert_file=_config(kwargs, 'VAULT_CYBERARK_CACERT_FILE', ''),
            fail_on_password_change=_config(
                kwargs, 'VAULT_CYBERARK_FAIL_ON_PASSWORD_CHANGE', True
            ),
        )

    def is_active(self):
        return self.client.is_active()

    def _get(self, entry):
        # Only asset accounts exist in CyberArk. Templates, personal
        # credentials and historical records keep using the local database.
        if not getattr(entry, 'ccp_capable', False):
            return None

        values = entry.ccp_values
        try:
            query = build_query(
                self.client.query_template,
                safe=values['safe'] or self.client.safe,
                folder=values['folder'] or self.client.folder,
                username=values['username'],
                address=values['address'],
                asset_name=values['asset_name'],
                account_name=values['account_name'],
                extra=values['extra'],
            )
            data = self.client.fetch(query, app_id=values['app_id'])
        except CyberArkCCPError as error:
            return self._fallback(error)

        if not _same_user(values['username'], data.get('username')):
            return self._fallback(CyberArkCCPError(
                'The resolved CyberArk object does not match the account username'
            ))

        secret = data.get('content')
        if not secret:
            return self._fallback(CyberArkCCPError(
                f'No secret returned for account "{values["username"]}"'
            ))
        return secret

    def _fallback(self, error):
        logger.warning('Read secret from CyberArk CCP failed: %s', error)
        if self.fallback_local:
            return None
        raise VaultUnavailableException() from error

    # -------- read-only backend -------- #

    def create(self, instance):
        """CyberArk CCP has no write API, keep the database secret as is."""

    def update(self, instance):
        """CyberArk CCP has no write API, keep the database secret as is."""

    def delete(self, instance):
        """CyberArk CCP has no write API, never delete the CyberArk object."""

    def _clean_db_secret(self, instance):
        """Never replace the local secret with the vault marker."""

    def _get_for_restore(self, entry):
        raise VaultException()

    # BaseVault declares these as abstract. They are never reached because the
    # public create/update/delete hooks above are no-ops, but the class cannot
    # be instantiated without them.

    def _create(self, entry):
        pass

    def _update(self, entry):
        pass

    def _delete(self, entry):
        pass

    def _save_metadata(self, entry, metadata):
        pass
