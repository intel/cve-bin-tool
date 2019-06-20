"""
CVE-bin-tool file tests
"""
import os
import sys
import unittest
import subprocess

from cve_bin_tool.file import is_binary

ASSETS_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "assests")
BINARIES_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "binaries")


class TestFile(unittest.TestCase):
    """ Tests the CVE Bin Tool file binary checker."""

    @classmethod
    def setUpClass(cls):
        # build binaries
        if sys.platform == "linux" or sys.platform == "linux2":
            subprocess.call(["make", "clean-linux"], cwd=BINARIES_PATH)
        elif sys.platform == "win32":
            subprocess.call(["make", "clean-windows"], cwd=BINARIES_PATH)
        subprocess.call(["make", "all"], cwd=BINARIES_PATH)

    def _check_test(self, filename, is_executable):
        """Helper function to parse a binary file and check whether
        the given string is in the parsed result"""
        self.assertEqual(
            is_binary(os.path.join(BINARIES_PATH, filename)), is_executable
        )

    def test_curl_7_34_0_out(self):
        """file test-curl-7.34.0.out"""
        self._check_test("test-curl-7.34.0.out", True)

    def test_curl_7_34_0_source(self):
        """file test-curl-7.34.0.c"""
        self._check_test("test-curl-7.34.0.c", False)

    def test_single_byte_file(self):
        """file single-byte"""
        self.assertFalse(is_binary(os.path.join(ASSETS_PATH, "single-byte.txt")))

    def test_windows(self):
        """file single-byte"""
        self.assertTrue(is_binary(os.path.join(ASSETS_PATH, "windows.txt")))
