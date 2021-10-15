import unittest
import subprocess
import os
import platform
import contextlib
import tempfile
import shutil

# You can use the KEEP_TEMP_FILES environment variable to tell the tests not to
# clean up after themselves, which can help with debugging.
KEEP_TEMP_FILES = os.getenv("KEEP_TEMP_FILES", "") != ""


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
    def do_stamp(self, source):
        base = os.path.basename(source)
        binary = os.path.splitext(base)[0]
        gtirb = f"{binary}.gtirb"
        stamped_gtirb = f"{binary}.gtirb.stamp"
        stamped = f"{binary}.stamp"

        class TempDir:
            def __init__(self, prefix):
                self.prefix = prefix

            def __enter__(self):
                self.dir = tempfile.mkdtemp(
                    prefix=self.prefix + "-tmp-", dir=os.getcwd()
                )
                return self.dir

            def __exit__(self, type, value, traceback):
                shutil.rmtree(self.dir)

        es = contextlib.ExitStack()
        tempdir = es.enter_context(TempDir(binary))
        try:
            shutil.copy(source, os.path.join(tempdir, source))
            if platform.system() == "Linux":
                args = ["make", binary, "-B"]
                ec = subprocess.call(args, cwd=tempdir)
                self.assertEqual(ec, 0)

            args = [self._ddisasm, binary, "--ir", gtirb]
            ec = subprocess.call(args, cwd=tempdir)
            self.assertEqual(ec, 0)

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
            ec = subprocess.call(args, cwd=tempdir)
            self.assertEqual(ec, 0)
            yield (os.path.join(tempdir, file) for file in (binary, stamped))
        finally:
            if KEEP_TEMP_FILES:
                print(
                    "KEEP_TEMP_FILES is preserving test directory: " + tempdir
                )
                es.pop_all()
            es.close()

    def test_1_invocation(self):
        with self.do_stamp("factorial.c") as (binary, stamped):
            if platform.system() == "Linux":
                args = [stamped, "10"]
                output = subprocess.check_output(args)
                self.assertEqual(output, b"Factorial(10)=3628800\n")
        return True

    @unittest.skipUnless(
        platform.system() == "Linux",
        ("The test binary can't run on Windows."),
    )
    def test_stamp(self):
        with self.do_stamp("stack-overwrite.c") as (binary, stamped):
            args = [binary]
            output = subprocess.run(
                args, stdout=subprocess.PIPE
            ).stdout.decode("utf-8")
            self.assertIn("Function A", output)
            self.assertIn("Function B", output)
            args = [stamped]
            stamped_output = subprocess.run(
                args, stdout=subprocess.PIPE
            ).stdout.decode("utf-8")
            self.assertIn("Function A", stamped_output)
            self.assertNotIn("Function B", stamped_output)
            args = [stamped, "dont overwrite"]
            output = subprocess.check_output(args)
            self.assertIn("Function A", stamped_output)
            self.assertNotIn("Function B", stamped_output)
