import unittest
import mock
from flask import Response
from storage import redisclient
import view


class tests_view(unittest.TestCase):

    def setUp(self):
        self.app = view.app.test_client()
        self.app.testing = True

    def __init__(self, *args, **kwargs):
        redisclient('localhost', 6379, db=1)
        super(tests_view, self).__init__(*args, **kwargs)

    def test__view__test__whenCalledWithDummyValue__persistsReadsAndReturnsDummyValue(self):
        expected_value = 'OK wibble'
        returned_value = view.test('wibble')

        self.assertEqual(returned_value, expected_value, 'Test method did not return the expected value')

    def test__view__login__whenCalledWithNoScope_WillReturnInvalidRequest(self):

        data = {
            'response_type': 'code',
            'client_id': 's6BhdRkqt3',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})
        self.assertEqual(response.status_code, 400)
