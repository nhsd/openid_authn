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