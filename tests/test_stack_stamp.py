import unittest
import subprocess
import os


class StackStampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        args = ["make", "-C", "tests", "factorial"]
        ec = subprocess.call(args)
        return ec == 0

    def setUp(self):
        self._test_file = os.path.join("dist", "factorial")
        self.assertTrue(os.path.isfile(self._test_file))

    def test_1_invocation(self):
        return True
