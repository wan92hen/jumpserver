from django.test import SimpleTestCase

from accounts.backends.cyberark.service import (
    CyberArkCCPClient, CyberArkCCPError,
)
from accounts.mock_cyberark_ccp import (
    CyberArkCCPMock, MockAccount, start_in_thread,
)

__all__ = ['CyberArkMockServerTests', 'CyberArkMockUniqueMatchTests']


class CyberArkMockServerTests(SimpleTestCase):
    def setUp(self):
        self.mock = CyberArkCCPMock(
            accounts=[
                MockAccount(
                    safe='Linux', folder='Root', object_name='root',
                    username='root', address='10.0.0.1',
                    content='root-secret',
                ),
                MockAccount(
                    safe='Linux', folder='Root', object_name='svc-web',
                    username='svc-web', address='10.0.0.2',
                    content='svc-secret', password_change_in_process=True,
                ),
            ],
            app_ids={'JMS'},
        )
        self.mock.quiet = True
        self.server, self.thread, self.url = start_in_thread(self.mock)
        self.addCleanup(self._stop)
        self.client = CyberArkCCPClient(api_url=self.url, app_id='JMS')

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def test_password_is_returned_and_reason_is_recorded(self):
        data = self.client.fetch(
            'Safe=Linux;Folder=Root;UserName=root', reason='JMS-TEST'
        )
        self.assertEqual(data['content'], 'root-secret')
        self.assertEqual(data['username'], 'root')
        self.assertFalse(data['passwordchangeinprocess'])
        self.assertEqual(self.mock.requests[-1]['reason'], 'JMS-TEST')
        self.assertEqual(self.mock.requests[-1]['status'], 200)

    def test_unknown_object_returns_empty_payload(self):
        self.assertEqual(
            self.client.fetch('Safe=Linux;UserName=missing'), {}
        )
        self.assertEqual(self.mock.requests[-1]['status'], 400)

    def test_object_name_can_be_used(self):
        data = self.client.fetch('Safe=Linux;Object=root', reason='JMS-TEST')
        self.assertEqual(data['content'], 'root-secret')

    def test_unauthorized_app_id_raises(self):
        client = CyberArkCCPClient(api_url=self.url, app_id='OTHER')
        with self.assertRaises(CyberArkCCPError) as context:
            client.fetch('Safe=Linux;UserName=root')
        self.assertEqual(context.exception.status_code, 403)
        self.assertIn('APPAP006E', str(context.exception))

    def test_missing_app_id_raises(self):
        client = CyberArkCCPClient(api_url=self.url, app_id='')
        with self.assertRaises(CyberArkCCPError) as context:
            client.fetch('Safe=Linux;UserName=root')
        self.assertEqual(context.exception.status_code, 401)

    def test_password_change_in_process_raises(self):
        with self.assertRaises(CyberArkCCPError) as context:
            self.client.fetch('Safe=Linux;UserName=svc-web')
        self.assertIn('APPAP306E', str(context.exception))

    def test_password_change_can_be_returned_when_not_failing(self):
        client = CyberArkCCPClient(
            api_url=self.url, app_id='JMS', fail_on_password_change=False
        )
        data = client.fetch('Safe=Linux;UserName=svc-web')
        self.assertTrue(data['passwordchangeinprocess'])
        self.assertEqual(data['content'], 'svc-secret')

    def test_unsupported_attribute_raises(self):
        with self.assertRaises(CyberArkCCPError) as context:
            self.client.fetch('Safe=Linux;Unknown=value')
        self.assertEqual(context.exception.status_code, 400)
        self.assertIn('Unsupported query attribute', str(context.exception))

    def test_is_active_against_the_mock(self):
        self.assertEqual(self.client.is_active(), (True, ''))

    def test_is_active_reports_wrong_app_id(self):
        client = CyberArkCCPClient(api_url=self.url, app_id='OTHER')
        ok, message = client.is_active()
        self.assertFalse(ok)
        self.assertIn('APPAP006E', message)


class CyberArkMockUniqueMatchTests(SimpleTestCase):
    def setUp(self):
        self.mock = CyberArkCCPMock(
            accounts=[
                MockAccount(safe='Linux', object_name='a', username='root',
                            address='10.0.0.1', content='a'),
                MockAccount(safe='Linux', object_name='b', username='root',
                            address='10.0.0.2', content='b'),
            ],
            app_ids={'JMS'}, unique_match=True,
        )
        self.mock.quiet = True
        self.server, self.thread, self.url = start_in_thread(self.mock)
        self.addCleanup(self._stop)

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def test_ambiguous_query_is_rejected(self):
        client = CyberArkCCPClient(api_url=self.url, app_id='JMS')
        with self.assertRaises(CyberArkCCPError) as context:
            client.fetch('Safe=Linux;UserName=root')
        self.assertIn('2 objects match', str(context.exception))

    def test_address_narrows_the_query(self):
        client = CyberArkCCPClient(api_url=self.url, app_id='JMS')
        data = client.fetch('Safe=Linux;UserName=root;Address=10.0.0.2')
        self.assertEqual(data['content'], 'b')
