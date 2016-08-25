import unittest
import mock
from storage import redisclient
import view


class tests_view(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        redisclient('localhost', 6379, db=1)
        super(tests_view, self).__init__(*args, **kwargs)


    def test__view__test__whenCalledWithDummyValue__persistsReadsAndReturnsDummyValue(self):
        expected_value = 'OK wibble'
        returned_value = view.test('wibble')

        self.assertEqual(returned_value, expected_value, 'Test method did not return the expected value')


