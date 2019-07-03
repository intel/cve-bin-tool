"""
csv2cve tests
"""

import os
import unittest
from cve_bin_tool.csv2cve import csv2cve


class TestCsv2cve(unittest.TestCase):
    """
    Runs tests for the csv2cve helper tool
    """

    @classmethod
    def setUp(self):
        self.CSV_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

    def test_bad_csv(self):
        output = csv2cve(os.path.join(self.CSV_PATH, "bad.csv"))
        self.assertEqual(-1, output)

    def test_bad_vendor(self):
        output = csv2cve(os.path.join(self.CSV_PATH, "bad_vendor.csv"))
        self.assertEqual(-2, output)

    def test_bad_package(self):
        output = csv2cve(os.path.join(self.CSV_PATH, "bad_package.csv"))
        self.assertEqual(-2, output)

    def test_bad_version(self):
        output = csv2cve(os.path.join(self.CSV_PATH, "bad_version.csv"))
        self.assertEqual(-2, output)

    def test_sample_csv(self):
        output = csv2cve(os.path.join(self.CSV_PATH, "test.csv"))
        self.assertIn("CVE-2018-19664", output[0])
        self.assertIn("CVE-2018-0500", output[1])
        self.assertIn("CVE-2018-1000300", output[1])
        self.assertIn("CVE-2018-14618", output[2])
