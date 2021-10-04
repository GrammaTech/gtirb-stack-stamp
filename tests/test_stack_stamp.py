import unittest
import subprocess
import os
import platform
import contextlib


class StackStampTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir("tests")

    def setUp(self):
        if platform.system() == "Linux":
            self._ddisasm = "ddisasm"
        elif platform.system() == "Windows":
            self._ddisasm = "ddisasm.exe"

    @contextlib.contextmanager
    def do_stamp(self, binary):
        @contextlib.contextmanager
        def temp_file(path):
            try:
                yield path
            finally:
                os.remove(path)

        es = contextlib.ExitStack()
        try:
            args = ["make", binary, "-B"]
            ec = subprocess.call(args)
            self.assertEqual(ec, 0)
            es.enter_context(temp_file(binary))

            gtirb = f"{binary}.gtirb"
            stamped_gtirb = f"{binary}.gtirb.stamp"
            stamped = f"{binary}.stamp"

            args = [self._ddisasm, binary, "--ir", gtirb]
            ec = subprocess.call(args)
            self.assertEqual(ec, 0)
            es.enter_context(temp_file(gtirb))

            if platform.system() == "Linux":
                python = "python3"
            elif platform.system() == "Windows":
                python = "python"

            args = [
                python,
                "-m",
                "gtirb_stack_stamp",
                gtirb,
                "--outfile",
                stamped_gtirb,
            ]
            # On windows, gtirb-pprinter can't binary print an ELF file, so
            # only do that part of the test on linux
            if platform.system() == "Linux":
                args += ["--rebuild", stamped]
            ec = subprocess.call(args)
            self.assertEqual(ec, 0)
            es.enter_context(temp_file(stamped_gtirb))
            es.enter_context(temp_file(stamped))
            yield stamped
        finally:
            es.close()

    def test_1_invocation(self):
        with self.do_stamp("factorial") as stamped:
            if platform.system() == "Linux":
                args = [f"./{stamped}", "10"]
                output = subprocess.check_output(args)
                self.assertEqual(output, b"Factorial(10)=3628800\n")
        return True

    @unittest.skipUnless(
        platform.system() == "Linux",
        (
            "The test binary can't run on Windows, and test_1_invocation "
            "already tests that the stamp itself runs on Windows."
        ),
    )
    def test_stamp(self):
        binary = "stack-overwrite"
        with self.do_stamp(binary) as stamped:
            if platform.system() == "Linux":
                args = [f"./{binary}"]
                output = subprocess.run(
                    args, stdout=subprocess.PIPE
                ).stdout.decode("utf-8")
                self.assertIn("Function A", output)
                self.assertIn("Function B", output)
                args = [f"./{stamped}"]
                stamped_output = subprocess.run(
                    args, stdout=subprocess.PIPE
                ).stdout.decode("utf-8")
                self.assertIn("Function A", stamped_output)
                self.assertNotIn("Function B", stamped_output)
