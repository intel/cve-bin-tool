"""
CVE-bin-tool CLI tests
"""
import os
import unittest
from cve_bin_tool.cli import main
from cve_bin_tool.extractor import Extractor

from .test_definitions import (
    TempDirTest,
    download_file,
    CURL_7_20_0_RPM,
    CURL_7_20_0_URL,
    TMUX_DEB_NAME,
    TMUX_DEB,
)


class TestCLI(TempDirTest):
    """ Tests the CVE Bin Tool CLI"""

    @classmethod
    def setUpClass(cls):
        super(TestCLI, cls).setUpClass()
        download_file(CURL_7_20_0_URL, os.path.join(cls.tempdir, CURL_7_20_0_RPM))
        download_file(TMUX_DEB, os.path.join(cls.tempdir, TMUX_DEB_NAME))

    def test_extract_curl_7_20_0(self):
        """Scanning curl-7.20.0"""
        self.assertNotEqual(
            main(["cve-bin-tool", "-l", "debug", "-x", self.tempdir]), 0
        )

    def test_binary_curl_7_20_0(self):
        """ Extracting from rpm and scanning curl-7.20.0 """
        with Extractor()() as ectx:
            extracted_path = ectx.extract(os.path.join(self.tempdir, CURL_7_20_0_RPM))
            self.assertNotEqual(
                main(
                    [
                        "cve-bin-tool",
                        "-l",
                        "debug",
                        os.path.join(extracted_path, "usr", "bin", "curl"),
                    ]
                ),
                0,
            )

    def test_no_extraction(self):
        """ Test scanner against curl-7.20.0 rpm with extraction turned off """
        self.assertEqual(
            main(["cve-bin-tool", os.path.join(self.tempdir, CURL_7_20_0_RPM)]), 0
        )

    def test_usage(self):
        """ Test that the usage returns 0 """
        self.assertEqual(main(["cve-bin-tool"]), 0)

    def test_invalid_file_or_directory(self):
        """ Test behaviour with an invalid file/directory """
        self.assertEqual(main(["cve-bin-tool", "non-existant"]), -1)

    def test_multithread(self):
        """ Test Multithread mode """
        self.assertNotEqual(
            main(["cve-bin-tool", "-l", "debug", "-m", "-x", self.tempdir]), 0
        )

    def test_invalid_parameter(self):
        """ Test that invalid parmeters exit with expected error code.
       ArgParse calls sys.exit(2) for all errors, we've overwritten to -2 """

        # no directory specified
        with self.assertRaises(SystemExit) as exit:
            main(["cve-bin-tool", "--bad-param"])
        self.assertEqual(exit.exception.code, -2)

        # bad parameter (but good directory)
        with self.assertRaises(SystemExit) as exit:
            main(["cve-bin-tool", "--bad-param", self.tempdir])
        self.assertEqual(exit.exception.code, -2)

        # worse parameter
        with self.assertRaises(SystemExit) as exit:
            main(["cve-bin-tool", "--bad-param && cat hi", self.tempdir])
        self.assertEqual(exit.exception.code, -2)

        # bad parameter after directory
        with self.assertRaises(SystemExit) as exit:
            main(["cve-bin-tool", self.tempdir, "--bad-param;cat hi"])
        self.assertEqual(exit.exception.code, -2)

    @unittest.skipUnless(os.getenv("LONG_TESTS") == "1", "Skipping long tests")
    def test_update_flags(self):
        self.assertNotEqual(
            main(["cve-bin-tool", "-x", "-u", "never", self.tempdir]), 0
        )
        self.assertNotEqual(
            main(["cve-bin-tool", "-x", "--update", "daily", self.tempdir]), 0
        )
        self.assertNotEqual(main(["cve-bin-tool", "-x", "-u", "now", self.tempdir]), 0)
        with self.assertRaises(SystemExit) as exit:
            main(["cve-bin-tool", "-u", "whatever", self.tempdir])
        self.assertEqual(exit.exception.code, -2)
