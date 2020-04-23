"""
CVE-bin-tool Strings tests
"""
import os
import sys
import tempfile
import unittest
import subprocess

from cve_bin_tool.strings import Strings

BINARIES_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "binaries")


class TestStrings(unittest.TestCase):
    """ Tests the CVE Bin Tool Strings"""

    @classmethod
    def setUpClass(cls):
        # build binaries
        if sys.platform == "linux" or sys.platform == "linux2":
            subprocess.call(["make", "clean-linux"], cwd=BINARIES_PATH)
        elif sys.platform == "win32":
            subprocess.call(["make", "clean-windows"], cwd=BINARIES_PATH)
        subprocess.call(["make", "all"], cwd=BINARIES_PATH)
        cls.strings = Strings()

    def _parse_test(self, filename):
        """Helper function to parse a binary file and check whether
        the given string is in the parsed result"""
        self.strings.filename = os.path.join(BINARIES_PATH, filename)
        f = tempfile.TemporaryFile()
        subprocess.call(["strings", self.strings.filename], stdout=f)
        binutils_strings = f.readlines()
        ours = self.strings.parse().split("\n")
        for theirs in binutils_strings:
            self.assertIn(theirs.decode("utf-8"), ours)

    def test_curl_7_34_0(self):
        """Stringsing test-curl-7.34.0.out"""
        self._parse_test("test-curl-7.34.0.out")

    def test_kerberos_1_15_1(self):
        """Stringsing test-kerberos-5-1.15.1.out"""
        self._parse_test("test-kerberos-5-1.15.1.out")
