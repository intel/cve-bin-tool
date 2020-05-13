"""
CVE-bin-tool CLI tests
"""
import logging
import os
import subprocess
import unittest

from cve_bin_tool.cli import main
from cve_bin_tool.cvedb import DISK_LOCATION_DEFAULT
from cve_bin_tool.extractor import Extractor
from .utils import (
    TempDirTest,
    download_file,
    CURL_7_20_0_RPM,
    CURL_7_20_0_URL,
    TMUX_DEB_NAME,
    TMUX_DEB,
    LONG_TESTS,
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

    @unittest.skipUnless(LONG_TESTS() > 0, "Skipping long tests")
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

    def check_checkers_log(self, cm, skip_checkers, include_checkers):
        # The final log has all the checkers detected
        final_log = [i for i in cm.output if "Checkers:" in i]
        self.assertTrue(len(final_log) > 0, "Could not find checkers line in log")
        final_log = final_log[0]
        for checker in skip_checkers:
            self.assertTrue(
                checker not in final_log, f"found skipped checker {checker}"
            )

        for checker in include_checkers:
            self.assertTrue(
                checker in final_log, f"could not find expected checker {checker}",
            )

    def test_skips(self):
        """Tests the skips option"""

        logger = logging.getLogger()
        test_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

        skip_checkers = ["systemd", "xerces", "xml2", "kerberos"]
        include_checkers = ["expat", "libgcrypt", "openssl", "sqlite"]

        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", test_path, "-s", ",".join(skip_checkers)])

        self.check_checkers_log(cm, skip_checkers, include_checkers)

        # swap skip_checkers and include_checkers
        include_checkers, skip_checkers = skip_checkers, include_checkers
        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", test_path, "-s", ",".join(skip_checkers)])

        self.check_checkers_log(cm, skip_checkers, include_checkers)

    def test_runs(self):
        logger = logging.getLogger()
        test_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")
        runs = ["expat", "libgcrypt", "openssl", "sqlite"]
        skip_checkers = ["systemd", "xerces", "xml2", "kerberos"]
        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", test_path, "-r", ",".join(runs)])
        self.check_checkers_log(cm, skip_checkers, runs)

        runs, skip_checkers = skip_checkers, runs
        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", test_path, "-r", ",".join(runs)])
        self.check_checkers_log(cm, skip_checkers, runs)

    @unittest.skipUnless(LONG_TESTS() > 0, "Skipping long tests")
    def test_update(self):
        logger = logging.getLogger()
        test_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", "-u", "never", test_path])
        self.assertTrue(
            "INFO:cve_bin_tool.CVEDB:Updating CVE data. This will take a few minutes."
            not in cm.output
        )

        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", "-u", "daily", test_path])
        self.assertTrue(
            (
                "INFO:cve_bin_tool.CVEDB:Using cached CVE data (<24h old). Use -u now to update immediately."
                in cm.output
            )
            or (
                "INFO:cve_bin_tool.CVEDB:Updating CVE data. This will take a few minutes."
                in cm.output
            )
        )

        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", "-u", "now", test_path])
        db_path = DISK_LOCATION_DEFAULT
        self.assertTrue(
            ("WARNING:cve_bin_tool.CVEDB:Deleting cachedir " + db_path in cm.output)
            and (
                "INFO:cve_bin_tool.CVEDB:Updating CVE data. This will take a few minutes."
                in cm.output
            )
        )

        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", "-u", "latest", test_path])
        self.assertTrue(
            "INFO:cve_bin_tool.CVEDB:Updating CVE data. This will take a few minutes."
            in cm.output
        )

    def test_unknown_warning(self):
        """ Test that an "UNKNOWN" file generates a warning """
        logger = logging.getLogger()

        # build the unknown test file in test/binaries
        binaries_path = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "binaries"
        )
        unknown_filename = "test-png-unknown.out"
        subprocess.call(["make", unknown_filename], cwd=binaries_path)

        # Run against the "unknown" file
        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", os.path.join(binaries_path, unknown_filename)])

        warnings = [i for i in cm.output if "WARNING" in i]
        self.assertTrue(len(warnings) > 0)
        self.assertTrue("was detected with version UNKNOWN" in "".join(warnings))

    def test_quiet_mode(self):
        """ Test that an quite mode isn't generating any output """
        logger = logging.getLogger()

        # build the test file in test/binaries
        binaries_path = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "binaries"
        )
        filename = "test-python-3.7.1.out"
        subprocess.call(["make", filename], cwd=binaries_path)

        with self.assertLogs(logger, logging.INFO) as cm:
            main(["cve-bin-tool", "-q", os.path.join(binaries_path, filename)])
            logger.info("test")

        self.assertEqual(["INFO:root:test"], cm.output)
