from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from accounts.backends.cyberark.main import Vault
from accounts.backends.cyberark.service import (
    CyberArkCCPClient, CyberArkCCPError, build_query,
)
from accounts.exceptions import VaultUnavailableException
from accounts.models import Account, AccountTemplate

__all__ = [
    'CyberArkQueryTests', 'CyberArkClientTests', 'CyberArkVaultTests',
]


def make_response(status_code=200, payload=None, text=''):
    response = Mock()
    response.status_code = status_code
    response.text = text
    response.json.return_value = payload if payload is not None else {}
    return response


class CyberArkQueryTests(SimpleTestCase):
    def test_empty_conditions_are_dropped(self):
        query = build_query(
            'Safe={safe};Folder={folder};UserName={username}',
            safe='Linux', folder='', username='root',
        )
        self.assertEqual(query, 'Safe=Linux;UserName=root')

    def test_extra_query_is_appended(self):
        query = build_query(
            'Safe={safe};UserName={username}',
            safe='Linux', username='root', extra='PolicyID=UnixSSH',
        )
        self.assertEqual(query, 'Safe=Linux;UserName=root;PolicyID=UnixSSH')

    def test_reserved_characters_are_rejected(self):
        for value in ('root;Safe=Other', 'root=1'):
            with self.assertRaises(CyberArkCCPError):
                build_query('UserName={username}', username=value)

    def test_extra_query_with_separator_is_rejected(self):
        with self.assertRaises(CyberArkCCPError):
            build_query('UserName={username}', username='root', extra='A=1;B=2')

    def test_unknown_placeholder_is_rejected(self):
        with self.assertRaises(CyberArkCCPError):
            build_query('Safe={safe};PolicyID={policy}', safe='Linux')

    def test_empty_query_is_rejected(self):
        with self.assertRaises(CyberArkCCPError):
            build_query('Folder={folder}', folder='')


class CyberArkClientTests(SimpleTestCase):
    def make_client(self, **kwargs):
        params = {'api_url': 'https://ccp.example.com', 'app_id': 'JMS'}
        params.update(kwargs)
        return CyberArkCCPClient(**params)

    def test_endpoint_is_built_once(self):
        client = self.make_client()
        self.assertEqual(
            client.endpoint, 'https://ccp.example.com/AIMWebService/api/Accounts'
        )
        client = self.make_client(
            api_url='https://ccp.example.com/AIMWebService/api/Accounts'
        )
        self.assertEqual(
            client.endpoint, 'https://ccp.example.com/AIMWebService/api/Accounts'
        )

    def test_unknown_object_returns_empty_payload(self):
        client = self.make_client()
        client.session.get = Mock(return_value=make_response(
            400, {'ErrorCode': 'APPAP004E', 'ErrorMsg': 'Object not found'}
        ))
        self.assertEqual(client.fetch('Safe=Linux;UserName=root'), {})

    def test_password_change_in_process_is_rejected(self):
        client = self.make_client()
        client.session.get = Mock(return_value=make_response(
            200, {'Content': 'secret', 'PasswordChangeInProcess': True}
        ))
        with self.assertRaises(CyberArkCCPError):
            client.fetch('Safe=Linux;UserName=root')

    def test_reason_and_app_id_are_sent(self):
        client = self.make_client()
        client.session.get = Mock(return_value=make_response(
            200, {'Content': 'secret', 'UserName': 'root'}
        ))
        client.fetch('Safe=Linux;UserName=root', reason='JMS-TEST')
        _, kwargs = client.session.get.call_args
        self.assertEqual(kwargs['params']['Reason'], 'JMS-TEST')
        self.assertEqual(kwargs['params']['AppID'], 'JMS')
        self.assertEqual(kwargs['params']['FailRequestOnPasswordChange'], 'true')

    def test_app_id_is_optional(self):
        client = self.make_client(app_id='')
        client.session.get = Mock(return_value=make_response(
            200, {'Content': 'secret', 'UserName': 'root'}
        ))
        client.fetch('Safe=Linux;UserName=root', reason='JMS-TEST')
        _, kwargs = client.session.get.call_args
        self.assertNotIn('AppID', kwargs['params'])

    def test_is_active_accepts_object_not_found(self):
        client = self.make_client()
        client.session.get = Mock(return_value=make_response(
            400, {'ErrorCode': 'APPAP004E', 'ErrorMsg': 'Object not found'}
        ))
        self.assertEqual(client.is_active(), (True, ''))

    def test_is_active_reports_auth_error(self):
        client = self.make_client()
        client.session.get = Mock(return_value=make_response(
            403, {'ErrorCode': 'APPAP006E', 'ErrorMsg': 'Not authorized'}
        ))
        ok, message = client.is_active()
        self.assertFalse(ok)
        self.assertIn('APPAP006E', message)

    def test_is_active_without_api_url(self):
        client = self.make_client(api_url='')
        ok, message = client.is_active()
        self.assertFalse(ok)
        self.assertIn('API URL', message)


@patch('accounts.backends.cyberark.entries.load_labels', return_value=({}, {}))
class CyberArkVaultTests(SimpleTestCase):
    def make_vault(self):
        return Vault(VAULT_ENABLED=True, VAULT_BACKEND='cyberark')

    def make_entry(self, username='root'):
        return Vault.build_entry(
            self.make_vault(), Account(username=username, name=username)
        )

    def test_read_only_backend_keeps_local_secret(self, _labels):
        vault = self.make_vault()
        account = Account(secret='local-secret')
        vault.create(account)
        vault.update(account)
        vault.delete(account)
        self.assertEqual(account._secret, 'local-secret')

    def test_secret_is_returned_from_ccp(self, _labels):
        vault = self.make_vault()
        vault.client.fetch = Mock(return_value={
            'content': 'ccp-secret', 'username': 'root',
        })
        entry = self.make_entry()
        self.assertEqual(vault._get(entry), 'ccp-secret')

    def test_username_mismatch_falls_back(self, _labels):
        vault = self.make_vault()
        vault.client.fetch = Mock(return_value={
            'content': 'ccp-secret', 'username': 'another',
        })
        self.assertIsNone(vault._get(self.make_entry()))

    def test_domain_notation_is_ignored(self, _labels):
        vault = self.make_vault()
        vault.client.fetch = Mock(return_value={
            'content': 'ccp-secret', 'username': 'EXAMPLE\\root',
        })
        self.assertEqual(vault._get(self.make_entry()), 'ccp-secret')

    def test_error_falls_back_to_local_when_enabled(self, _labels):
        vault = self.make_vault()
        vault.client.fetch = Mock(side_effect=CyberArkCCPError('boom'))
        self.assertIsNone(vault._get(self.make_entry()))

    def test_error_raises_when_fallback_is_disabled(self, _labels):
        vault = self.make_vault()
        vault.fallback_local = False
        vault.client.fetch = Mock(side_effect=CyberArkCCPError('boom'))
        with self.assertRaises(VaultUnavailableException):
            vault._get(self.make_entry())

    def test_empty_secret_falls_back(self, _labels):
        vault = self.make_vault()
        vault.client.fetch = Mock(return_value={'content': '', 'username': 'root'})
        self.assertIsNone(vault._get(self.make_entry()))

    def test_non_account_entry_does_not_call_ccp(self, _labels):
        vault = self.make_vault()
        vault.client.fetch = Mock()
        entry = vault.build_entry(AccountTemplate(name='template', username='root'))
        self.assertIsNone(vault._get(entry))
        vault.client.fetch.assert_not_called()
