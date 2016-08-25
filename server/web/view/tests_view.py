import base64
import unittest
import mock
from flask import Response
from storage import redisclient
import view
import json
from datetime import datetime, time
from urllib.parse import urlparse, parse_qs

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


    def test__view__login__whenCalledWithNoResponseType_willRedurectWithInvalidRequest(self):

        data = {
            'scope': 'openid',
            'client_id': 's6BhdRkqt3',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        p = urlparse(response.location)
        args = parse_qs(p.query)

        self.assertEqual(args.get('error')[0], 'invalid_request')
        self.assertEqual(response.status_code, 302)

    def test__view__login__whenCalledWithInvalidResponseType_willRedirectWithUnsupportedResponseType(self):
        data = {
            'response_type': 'mess',
            'scope': 'openid',
            'client_id': 's6BhdRkqt3',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data,
                                environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        p = urlparse(response.location)
        args = parse_qs(p.query)

        self.assertEqual(args.get('error')[0], 'unsupported_response_type')
        self.assertEqual(response.status_code, 302)

    def test__view__login__whenCalledWithNoScope_willRedirectWithInvalidRequest(self):

        data = {
            'response_type': 'code',
            'client_id': 's6BhdRkqt3',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        p = urlparse(response.location)
        args = parse_qs(p.query)

        self.assertEqual(args.get('error')[0], 'invalid_request')
        self.assertEqual(response.status_code, 302)

    def test__view__login__whenCalledWithInvalidScope_willRedirectWithInvalidScope(self):

        data = {
            'response_type': 'code',
            'scope': 'nope',
            'client_id': 's6BhdRkqt3',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        p = urlparse(response.location)
        args = parse_qs(p.query)

        self.assertEqual(args.get('error')[0], 'invalid_scope')
        self.assertEqual(response.status_code, 302)

    def test__view__login__whenCalledWithNoClientId_willRedirectWithInvalidRequest(self):

        data = {
            'response_type': 'code',
            'scope': 'openid',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        p = urlparse(response.location)
        args = parse_qs(p.query)

        self.assertEqual(args.get('error')[0], 'invalid_request')
        self.assertEqual(response.status_code, 302)

    def test__view__login__whenCalledWithUnknownClientId_willRenderErrorPage(self):

        data = {
            'response_type': 'code',
            'scope': 'openid',
            'client_id': 'unknown',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb' }

        response = self.app.get('authorize', query_string=data,
                                environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        self.assertEqual(response.status_code, 200)

    def test__view__login__whenCalledWithNoState_willRedirectWithInvalidRequest(self):

        data = {
            'response_type': 'code',
            'scope': 'openid',
            'client_id': 'af0ifjsldkj',
            'redirect_uri': 'https%3A%2F%2Fclient.example.org%2Fcb'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

        p = urlparse(response.location)
        args = parse_qs(p.query)

        self.assertEqual(args.get('error')[0], 'invalid_request')
        self.assertEqual(response.status_code, 302)

    def test__view__login__whenCalledWithNoRedirect_willRenderErrorPage(self):

        data = {
            'response_type': 'code',
            'scope': 'nope',
            'client_id': 's6BhdRkqt3',
            'state': 'af0ifjsldkj'}

        response = self.app.get('authorize', query_string=data, environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})
        self.assertEqual(response.status_code, 200)

    def test__view__login__whenCalledWithInvalidRedirect_WillShowErrorPage(self):
        data = {
            'response_type': 'code',
            'scope': 'openid',
            'client_id': 'example',
            'state': 'af0ifjsldkj',
            'redirect_uri': 'nope'}

        response = self.app.get('authorize', query_string=data,
                                environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'})

    def test__view__get_token__whenCalled__returnsAValidJWTWithValidValues(self):
        expected_fields = ['iss', 'sub', 'aud', 'exp', 'iat']
        raw_returned_token = view.get_token('158616253415', '731983621552')
        decoded_token = base64.b64decode(raw_returned_token)
        returned_token = json.loads(decoded_token.decode('utf-8'))

        for field in expected_fields:
            self.assertTrue(field in returned_token, 'Field \'%s\' does not exist in the returned token %s' % (field, raw_returned_token))

        expected_min_iat_time = int(datetime.now().timestamp()) - 5
        expected_max_iat_time = expected_min_iat_time + 10
        expected_min_exp_time = expected_min_iat_time + 600 # Assumes 10 minute token lifetime
        expected_max_exp_time = expected_min_exp_time + 10

        self.assertGreaterEqual(returned_token['iat'], expected_min_iat_time, 'IAT field has a time that is less than the expected time of now minus 5 seconds')
        self.assertLessEqual(returned_token['iat'], expected_max_iat_time, 'IAT field has a time that is more than the expected time of now plus 5 seconds')

        self.assertGreaterEqual(returned_token['exp'], expected_min_exp_time, 'EXP field has a time that is less than the expected time of now plus 595 seconds')
        self.assertLessEqual(returned_token['exp'], expected_max_exp_time, 'EXP field has a time that is more than the expected time of now plus 605 seconds')

        self.assertGreaterEqual(len(returned_token['sub']), 8, 'SUB field has a length that is less than the minimum expected 8 characters')
        self.assertLessEqual(len(returned_token['sub']), 255, 'SUB field has a length that is more than the valid length of 255 characters')

        self.assertTrue(str(returned_token['iss']).startswith('https://'), 'ISS field does not have the expected \'https://\' prefix')
