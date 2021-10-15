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

        with contextlib.ExitStack() as es:
            tempdir = es.enter_context(TempDir(binary))
            if KEEP_TEMP_FILES:
                es.pop_all()
                msg = "KEEP_TEMP_FILES is preserving test directory: "
                es.callback(lambda: print(msg, tempdir))

            if platform.system() == "Linux":
                shutil.copy(source, os.path.join(tempdir, source))
                args = ["make", binary, "-B"]
                ec = subprocess.call(args, cwd=tempdir)
                self.assertEqual(ec, 0)
            elif platform.system() == "Windows":
                shutil.copy(binary, os.path.join(tempdir, binary))

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
            # Check that the stamped program's behavior is unchanged when we
            # don't overwrite the return address
            self.assertEqual(
                subprocess.check_output([binary, "don't overwrite"]),
                subprocess.check_output([stamped, "don't overwrite"]),
            )
            # Check that stamping blocks return address overwrites
            unstamped_output = subprocess.run(
                [binary], stdout=subprocess.PIPE
            ).stdout
            stamped_output = subprocess.run(
                [stamped], stdout=subprocess.PIPE
            ).stdout
            self.assertTrue(unstamped_output.startswith(stamped_output))
            self.assertNotEqual(unstamped_output, stamped_output)
