import unittest
import subprocess
import os


class StackStampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir("tests")
        args = ["make", "factorial", "-B"]
        ec = subprocess.call(args)
        return ec == 0

    def setUp(self):
        self._test_file = "factorial"
        self.assertTrue(os.path.isfile(self._test_file))

    def test_1_invocation(self):
        args = ["ddisasm", "factorial", "--ir", "factorial.gtirb"]
        ec = subprocess.call(args)
        self.assertEqual(ec, 0)

        args = [
            "python3",
            "-m",
            "gtirb_stack_stamp",
            "factorial.gtirb",
            "--outfile",
            "factorial.gtirb.stamp",
            "--rebuild",
            "factorial.stamp",
        ]
        ec = subprocess.call(args)
        self.assertEqual(ec, 0)

        args = ["./factorial.stamp", "10"]
        output = subprocess.check_output(args)
        self.assertEqual(output, "Factorial(10)=3628800")
        return True
