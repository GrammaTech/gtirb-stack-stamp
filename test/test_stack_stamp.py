import unittest
import subprocess

class StackStampTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        args = ['make', 'factorial']
        ec = subprocess.call(args)
        self.assertEqual(ec, 0)

    def test_1_invocation(self):
        return True

