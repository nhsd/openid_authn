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