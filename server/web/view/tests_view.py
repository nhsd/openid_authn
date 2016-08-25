import unittest
import mock
from storage import redisclient
import view
import json
from datetime import datetime, time


class tests_view(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        redisclient('localhost', 6379, db=1)
        super(tests_view, self).__init__(*args, **kwargs)


    def test__view__test__whenCalledWithDummyValue__persistsReadsAndReturnsDummyValue(self):
        expected_value = 'OK wibble'
        returned_value = view.test('wibble')

        self.assertEqual(returned_value, expected_value, 'Test method did not return the expected value')


    def test__view__get_token__whenCalled__returnsAValidJWTWithValidValues(self):
        expected_fields = ['iss', 'sub', 'aud', 'exp', 'iat']
        raw_returned_token = view.get_token('session_id')
        returned_token = json.loads(raw_returned_token)

        for field in expected_fields:
            self.assertTrue(field in returned_token, 'Field \'%s\' does not exist in the returned token %s' % (field, raw_returned_token))

        expected_min_iat_time = int(datetime.now().strftime("%s")) - 5
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



