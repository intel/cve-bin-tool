"""
CVE-bin-tool tests
"""
import os
import re
import subprocess
import sys
import unittest

from cve_bin_tool.NVDAutoUpdate import NVDSQLite
from cve_bin_tool.cli import Scanner

BINARIES_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                             'binaries')

class TestScanner(unittest.TestCase):
    """Runs a series of tests against our "faked" binaries.

    The faked binaries are very small c files containing the same string signatures we use
    in the cve-bin-tool.  They should trigger results as if they contained the library and
    version specified in the file name.

    At this time, the tests work only in python3.
    """

    @classmethod
    def setUpClass(cls):
        # Run makefile to build faked binaries (in python 3 or 2)
        subprocess.call(["make", "clean"], cwd=BINARIES_PATH)
        subprocess.call(["make", "all"], cwd=BINARIES_PATH)
        # Instantiate the NVD database
        cls.nvd = NVDSQLite()
        cls.nvd.get_cvelist_if_stale()
        # Instantiate a scanner
        cls.scanner = Scanner(cls.nvd)

    def setUp(self):
        self.nvd.open()

    def tearDown(self):
        self.nvd.close()

    def scan_file(self, filename):
        return self.scanner.scan_file(os.path.join(BINARIES_PATH, filename))

    def test_vendor_package_pairs(self):
        pairs = list(self.scanner.vendor_package_pairs('\n'.join([
            'VPkg: haxx, curl',
            'VPkg: feed, face'
            ])))
        self.assertTrue(pairs)
        self.assertIn('haxx', dict(pairs))
        self.assertIn('curl', dict(map(lambda x: x[::-1], pairs)))
        self.assertIn('feed', dict(pairs))
        self.assertIn('face', dict(map(lambda x: x[::-1], pairs)))

    def test_cannot_open_file(self):
        with self.assertRaises(ValueError):
            self.scan_file('non-existant-file')

    def _binary_test(self, binary, package, version, are_in, not_in):
        """ Helper function to scan a binary and check that it contains certain
        cves for a version and doesn't contain others."""
        # Run the scan
        cves = self.scan_file(binary)
        # Make sure the package and version are in the results
        self.assertIn(package, cves)
        self.assertIn(version, cves[package])
        # Test for CVEs known in this version
        for ensure_in in are_in:
            self.assertIn(ensure_in, cves[package][version])
        # Test for a CVE that is not in this version
        for ensure_out in not_in:
            self.assertNotIn(ensure_out, cves[package][version])

    def test_curl_7_57_0(self):
        """Scanning test-curl-7.57.0.out"""
        self._binary_test('test-curl-7.57.0.out', 'curl', '7.57.0', [
            'CVE-2018-1000122',
            'CVE-2018-1000121',
            'CVE-2018-1000120',
            'CVE-2018-1000007',
            # NOTE Missing from NVD as of 1/14/2019, reported to NVD
            # 'CVE-2018-1000005',
            ], [
            'CVE-2017-8818',
            ])

    def test_expat_2_0_1(self):
        """Scanning test-expat-2.0.1.out"""
        # TODO Commented out issues have to do with less than X.X.X version
        # issue with NVD. Issue #29
        self._binary_test('test-expat-2.0.1.out', 'expat', '2.0.1', [
            # Check for issues specific to expat 2.0.1
            "CVE-2012-1147",
            # "CVE-2009-3720",
            # "CVE-2009-3560",
            "CVE-2012-1148",
            "CVE-2012-0876",

            # Check for other issues from more recent versions
            # 2.1
            "CVE-2016-0718",
            # "CVE-2016-4472",
            # "CVE-2016-5300",
            # "CVE-2012-6702",
            # "CVE-2015-1283",

            # 2.2
            # "CVE-2017-9233",
            # "CVE-2016-9063",
            "CVE-2016-0718",
            # "CVE-2017-11742",
            ], [
            'CVE-blahblah',
            ])

    def test_node_9_3_0(self):
        """Scanning test-node-9.3.0.out"""
        cves = self.scan_file("test-node-9.3.0.out")
        self._binary_test('test-node-9.3.0.out', 'node', '9.3.0', [
            # Check for known cves in 9.3.0
            "CVE-2017-15896",
            "CVE-2017-15897",
            ], [
            # Check to make sure an older CVE from 8.7.0 isn't included
            "CVE-2017-14919",
            ])

    def test_nss_3_35(self):
        """Scanning test-nss-3.55.out"""
        self._binary_test('test-nss-3.35.out', 'nss', '3.35', [
            # Check for known cves in 3.35
            "CVE-2017-11695",
            "CVE-2017-11696",
            "CVE-2017-11697",
            "CVE-2017-11698",
            ], [
            # Check to make sure an older CVE from 3.30.1 isn't included
            "CVE-2017-7502",
            ])

    def test_openssl_1_0_2g(self):
        """Scanning test-openssl-1.0.2g.out"""
        self._binary_test('test-openssl-1.0.2g.out', 'openssl', '1.0.2g', [
            # Check for known cves in this version
            "CVE-2016-2107",
            "CVE-2016-2105",
            "CVE-2016-2106",
            "CVE-2016-2109",
            "CVE-2016-2176",
            ], [
            # Check to make sure an older CVE isn't included
            "CVE-2016-0800",
            ])

    def test_png_1_6_26(self):
        """Scanning test-png-1.6.26.out"""
        self._binary_test('test-png-1.6.26.out', 'png', '1.6.26', [
            # Check for known cves in this version
            "CVE-2016-10087",
            ], [
            # Check to make sure an older CVE isn't included
            "CVE-2015-8126",
            ])

    def test_tiff_4_0_9(self):
        """Scanning test-tiff-4.0.9.out"""
        self._binary_test('test-tiff-4.0.9.out', 'tiff', '4.0.9', [
            # Check for known cves in this version
            "CVE-2017-18013",
            "CVE-2017-17942",
            "CVE-2017-17095",
            "CVE-2018-5784",
            "CVE-2018-7456",
            "CVE-2018-8905",
            ], [
            # Check to make sure an older CVE isn't included
            "CVE-2017-17973",
            ])

    def test_xerces_3_1_1(self):
        """Scanning test-xerces-3_1_1.out"""
        self._binary_test('test-xerces-3_1_1.out', 'xerces', '3.1.1', [
            # Check for known cves in this version
            "CVE-2015-0252",
            ], [
            # Check to make sure an older CVE isn't included
            "CVE-EOL-DONOTUSE",
            ])

    def test_xml2_2_9_0(self):
        """Scanning test-xml2-2.9.0.out"""
        self._binary_test('test-xml2-2.9.0.out', 'xml2', '2.9.0', [
            # Check for known cves in this version
            "CVE-2013-0338",
            "CVE-2013-1969",
            ], [
            # Check to make sure an older CVE isn't included
            "CVE-2011-1944",
            ])

    def test_zlib_1_2_8(self):
        """Scanning test-zlib-1.2.8.out"""
        self._binary_test('test-zlib-1.2.8.out', 'zlib', '1.2.8', [
            # Check for known cves in this version
            "CVE-2016-9843",
            "CVE-2016-9842",
            "CVE-2016-9841",
            "CVE-2016-9840",
            ], [
            # Check to make sure an older CVE isn't included
            "CVE-2005-2096",
            ])
