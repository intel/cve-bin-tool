"""
CVE-bin-tool CLI tests
"""
import os
import re

from cve_bin_tool.cli import main
from cve_bin_tool.extractor import Extractor

from .test_definitions import TempDirTest, \
                              download_file, \
                              CURL_7_20_0_RPM, \
                              CURL_7_20_0_URL

class TestCLI(TempDirTest):
    """ Tests the CVE Bin Tool CLI"""

    @classmethod
    def setUpClass(cls):
        super(TestCLI, cls).setUpClass()
        download_file(CURL_7_20_0_URL,
                      os.path.join(cls.tempdir, CURL_7_20_0_RPM))

    def test_extract_curl_7_20_0(self):
        """Scanning curl-7.20.0"""
        self.assertNotEqual(main(['cve-bin-tool', '-l', 'debug', '-x',
                                  self.tempdir]), 0)

    def test_binary_curl_7_20_0(self):
        with Extractor()() as ectx:
            extracted_path = ectx.extract(os.path.join(self.tempdir,
                                                       CURL_7_20_0_RPM))
            self.assertNotEqual(main(['cve-bin-tool', '-l', 'debug',
                                      os.path.join(extracted_path, 'usr', 'bin',
                                                   'curl')]), 0)

    def test_no_extraction(self):
        self.assertEqual(main(['cve-bin-tool',
                               os.path.join(self.tempdir, CURL_7_20_0_RPM)]),
                               0)

    def test_usage(self):
        self.assertEqual(main(['cve-bin-tool']), 0)

    def test_invalid_file_or_directory(self):
        self.assertEqual(main(['cve-bin-tool', 'non-existant']), 0)
