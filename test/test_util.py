"""
CVE-bin-tool util tests
"""
import unittest

from cve_bin_tool.util import inpath


class TestUtil(unittest.TestCase):
    """ Test the util functions """

    def test_inpath(self):
        """ Test the check to see if a command line utility is installed
        and in path before we try to run it. """
        self.assertTrue(inpath("python"))

    def test_not_inpath(self):
        self.assertFalse(inpath("cve_bin_tool_test_for_not_in_path"))
