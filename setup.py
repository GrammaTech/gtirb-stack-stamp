from setuptools import setup, find_packages
import unittest


def gtirb_stack_stamp_test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover("tests", pattern="test_*.py")
    return test_suite


if __name__ == "__main__":
    setup(
        name="gtirb-stack-stamp",
        version="0.0.0",
        author="blevine",
        author_email="blevine@grammatech.com",
        description="Apply a stack-stamp transform to GTIRB",
        package_data={"gtirb_stack_stamp": ["gtirb_stack_stamp/*.py"]},
        packages=find_packages(),
        test_suite="setup.gtirb_stack_stamp_test_suite",
        install_requires=["gtirb", "pyyaml"],
        classifiers=["Programming Language :: Python :: 3"],
        entry_points={
            "console_scripts": [
                "stack-stamp = stack_stamp.__main__:main"
            ]
        },
    )
