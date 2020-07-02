import unittest
import subprocess
import os
import platform


class StackStampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir("tests")
        if platform.system() == "Linux":
            args = ["make", "factorial", "-B"]
            ec = subprocess.call(args)
            return ec == 0
        return True

    def setUp(self):
        self._test_file = "factorial"
        if platform.system() == "Linux":
            self._ddisasm = "ddisasm"
        elif platform.system() == "Windows":
            self._ddisasm = "ddisasm.exe"
        self.assertTrue(os.path.isfile(self._test_file))

    def test_1_invocation(self):
        args = [self._ddisasm, self._test_file, "--ir", "factorial.gtirb"]
        ec = subprocess.call(args)
        self.assertEqual(ec, 0)

        if platform.system() == "Linux":
            python = "python3"
        elif platform.system() == "Windows":
            python = "python"

        args = [
            python,
            "-m",
            "gtirb_stack_stamp",
            "factorial.gtirb",
            "--outfile",
            "factorial.gtirb.stamp",
        ]
        # On windows, gtirb-pprinter can't binary print an ELF file, so only do
        # that part of the test on linux
        if platform.system() == "Linux":
            args += ["--rebuild", "factorial.stamp"]
        ec = subprocess.call(args)
        self.assertEqual(ec, 0)

        if platform.system() == "Linux":
            args = ["./factorial.stamp", "10"]
            output = subprocess.check_output(args)
            self.assertEqual(output, b"Factorial(10)=3628800\n")
        return True
