"""
csv2cve tests
"""

import os
import sys
import unittest
from cve_bin_tool.csv2cve import CSV2CVE, main


class TestCsv2cve(unittest.TestCase):
    """
    Runs tests for the csv2cve helper tool
    """

    @classmethod
    def setUp(self):
        self.CSV_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

    def test_bad_csv(self):
        """ Test a empty csv file (should fail) """
        csv2cve = CSV2CVE(filename=os.path.join(self.CSV_PATH, "bad.csv"))
        output = csv2cve.generate_modules()
        self.assertEqual(-1, output)

    def test_bad_vendor(self):
        """ Test a csv file with a bad vendor column (should fail) """
        csv2cve = CSV2CVE(filename=os.path.join(self.CSV_PATH, "bad_vendor.csv"))
        output = csv2cve.generate_modules()
        self.assertEqual(-2, output)

    def test_bad_product(self):
        """ Test a csv file with a bad product column (should fail) """
        csv2cve = CSV2CVE(filename=os.path.join(self.CSV_PATH, "bad_product.csv"))
        output = csv2cve.generate_modules()
        self.assertEqual(-2, output)

    def test_bad_version(self):
        """ Test a csv file with a bad version column (should fail) """
        csv2cve = CSV2CVE(filename=os.path.join(self.CSV_PATH, "bad_version.csv"))
        output = csv2cve.generate_modules()
        self.assertEqual(-2, output)

    def test_bad_filename(self):
        """ Test a csv with bad filename (should fail)"""
        csv2cve = CSV2CVE(filename="I'm not a good path")
        output = csv2cve.generate_modules()
        self.assertEqual(-3, output)

    def test_sample_csv(self):
        """ Test a good sample CSV file (also contains false products)"""
        csv2cve = CSV2CVE(filename=os.path.join(self.CSV_PATH, "test.csv"))
        output = csv2cve.generate_modules()

        # Generate Dict Keys for Testting
        pro_libjpeg = output["libjpeg-turbo"]["2.0.1"].keys()
        pro_curl = output["curl"]["7.59.0"].keys()
        pro_libcurl = output["libcurl"]["7.59.0"].keys()
        pro_unknown = output["no"]["7.7"].keys()

        # Assert the CVEs in the dict keys
        self.assertIn("CVE-2018-19664", pro_libjpeg)
        self.assertIn("CVE-2018-16839", pro_curl)
        self.assertIn("CVE-2018-16890", pro_libcurl)
        self.assertIn("UNKNOWN", pro_unknown)

    def test_main(self):
        """ Test running main. Likely needs to be expanded. """
        returncode = main(["csv2cve"])
        self.assertEqual(0, returncode)
