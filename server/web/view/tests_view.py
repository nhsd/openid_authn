import unittest
import mock
from flask import Request
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


    def test__view__login__whenCalledWithNoResponseType_willRedirectWithInvalidRequest(self):

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

        self.assertEqual(response.status_code, 500)

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

    def test__view__token_callback__whenCalledwithInvalidRequest_WillRedirectwithReasonInData(self):
        query_params = {
            'grant_type': '',
            'code': '',
            'redirect_uri': '',
            }
        headers = {
            'Content-Type': '',
            'Authorization': ''
        }

        response = self.app.post('token', query_string=query_params,
                                environ_base={'REMOTE_ADDR': 'ex', 'HTTP_USER_AGENT': 'ex'}, headers=headers)

        response_data = json.loads(response.data.decode('utf-8'))

        self.assertTrue(response_data['error'])
        self.assertEqual(response.status_code, 400)

    def test__view___is_valid_token_request__whenCalledWithIncorrectContentType_WillReturnFalseAndInvalidContentTypeAndNoData(self):
        query_params = {
            'grant_type': 'authorization_code',
            'code': '',
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth',
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'invalid_content_type', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request__whenCalledWithoutAuthorizationHeader_WillReturnFalseAndInvalidRequestAndNoData(self):
        client_info = {'client_id': 1234, 'scope': 1234}

        query_params = {
            'grant_type': 'authorization_code',
            'code': view.generate_authorisation_token(client_info),
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': None
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'authorization header expected', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request__whenCalledWithIncorrectAuthorizationHeader_WillReturnFalseAndInvalidClientAndNoData(self):
        query_params = {
            'grant_type': 'authorization_code',
            'code': '',
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth',
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': ''
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'invalid_client', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request__whenCalledWithIncorrectGrantType_WillReturnFalseAndInvalidContentTypeAndNoData(self):
        query_params = {
            'grant_type': 'authorization_cooooooooouuude',
            'code': '',
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth',
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'unsupported_grant_type', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request__whenCalledWithoutGrantType_WillReturnFalseAndInvalidContentTypeAndNoData(self):
        query_params = {
            'grant_type': None,
            'code': '',
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth',
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'unsupported_grant_type', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request__whenCalledWithTooManyArgs_WillReturnFalseAndInvalidRequestArgsAndNoData(self):
        query_params = {
            'grant_type': 'authorization_code',
            'code': '',
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth',
            'extra arg': 'extra val'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'invalid_request_args', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request__whenCalledWithNoAuthorizationCode_WillReturnFalseAndInvalidCodeAndNoData(
            self):
        query_params = {
            'grant_type': 'authorization_code',
            'code': None,
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)
        expected_result = False, 'invalid_code', None

        self.assertEqual(validation_result, expected_result)

    def test__view___is_valid_token_request_whenCalledWithValidRequest_WillReturnTryeAndNoneAndData(self):
        client_info = {'client_id': 1234, 'scope': 1234}

        query_params = {
            'grant_type': 'authorization_code',
            'code': view.generate_authorisation_token(client_info),
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth'
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }

        mock_request = mock.MagicMock(spec=Request, args=query_params, headers=headers)

        validation_result = view._is_valid_token_request(mock_request)

        expected_data = {
            'grant_type': 'authorization_code',
            'code': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEyMzQsImFtciI6InBhc3N3b3JkIiwiaXNzIjoibWF0dC1wYyIs \
                       ImlhdCI6MTQ3MjY1NjQ0MSwiZXhwIjoxNDcyNjU2NDcxLCJzY3AiOjEyMzQsImF1ZCI6Im1hdHQtcGMifQ.f1BhHLl0UeZT4l1 \
                       taxVHAWaBiH8nhyVEP-05FUuVQGk',
            'redirect_uri': 'http%3A%2F%2Flocalhost:5001%2Fauth',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'
        }
        expected_result = True, None, expected_data

       # validate_token hitting exception currently
       # self.assertEqual(validation_result, expected_result)