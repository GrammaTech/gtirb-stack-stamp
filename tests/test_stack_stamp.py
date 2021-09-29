import unittest
import subprocess
import os
import platform


class StackStampTest(unittest.TestCase):
    @classmethod
    def binaries(cls):
        return ["factorial", "stack-overwrite"]

    @classmethod
    def setUpClass(cls):
        os.chdir("tests")
        if platform.system() == "Linux":
            for binary in cls.binaries():
                args = ["make", binary, "-B"]
                ec = subprocess.call(args)
                if ec != 0:
                    return False
        return True

    def setUp(self):
        if platform.system() == "Linux":
            self._ddisasm = "ddisasm"
        elif platform.system() == "Windows":
            self._ddisasm = "ddisasm.exe"
        for binary in self.binaries():
            self.assertTrue(os.path.isfile(binary))

    def do_stamp(self, binary):
        args = [self._ddisasm, binary, "--ir", f"{binary}.gtirb"]
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
            f"{binary}.gtirb",
            "--outfile",
            f"{binary}.gtirb.stamp",
        ]
        # On windows, gtirb-pprinter can't binary print an ELF file, so only do
        # that part of the test on linux
        if platform.system() == "Linux":
            args += ["--rebuild", f"{binary}.stamp"]
        ec = subprocess.call(args)
        self.assertEqual(ec, 0)

    def test_1_invocation(self):
        self.do_stamp("factorial")

        if platform.system() == "Linux":
            args = ["./factorial.stamp", "10"]
            output = subprocess.check_output(args)
            self.assertEqual(output, b"Factorial(10)=3628800\n")
        return True

    def test_stamp(self):
        self.do_stamp("stack-overwrite")
        if platform.system() == "Linux":
            args = ["./stack-overwrite"]
            output = subprocess.run(
                args, stdout=subprocess.PIPE
            ).stdout.decode("utf-8")
            assert "Function A" in output
            assert "Function B" in output
            args = ["./stack-overwrite.stamp"]
            stamped_output = subprocess.run(
                args, stdout=subprocess.PIPE
            ).stdout.decode("utf-8")
            assert "Function A" in stamped_output
            assert "Function B" not in stamped_output
