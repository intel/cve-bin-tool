# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool CLI tests
"""
import json
import logging
import os
import tempfile
import unittest
from test.utils import (
    CURL_7_20_0_RPM,
    CURL_7_20_0_URL,
    LONG_TESTS,
    TMUX_DEB,
    TMUX_DEB_NAME,
    TempDirTest,
    download_file,
)

import pytest

from cve_bin_tool.cli import main
from cve_bin_tool.cvedb import DISK_LOCATION_DEFAULT
from cve_bin_tool.extractor import Extractor
from cve_bin_tool.version_scanner import VersionScanner


class TestCLI(TempDirTest):
    """Tests the CVE Bin Tool CLI"""

    TEST_PATH = os.path.abspath(os.path.dirname(__file__))

    def setup_method(self):
        download_file(CURL_7_20_0_URL, os.path.join(self.tempdir, CURL_7_20_0_RPM))
        download_file(TMUX_DEB, os.path.join(self.tempdir, TMUX_DEB_NAME))

    def test_extract_curl_7_20_0(self):
        """Scanning curl-7.20.0"""
        assert main(["cve-bin-tool", "-l", "debug", "-x", self.tempdir]) != 0

    def test_binary_curl_7_20_0(self):
        """Extracting from rpm and scanning curl-7.20.0"""
        with Extractor() as ectx:
            extracted_path = ectx.extract(os.path.join(self.tempdir, CURL_7_20_0_RPM))
            assert (
                main(
                    [
                        "cve-bin-tool",
                        "-l",
                        "debug",
                        os.path.join(extracted_path, "usr", "bin", "curl"),
                    ]
                )
                != 0
            )

    def test_no_extraction(self):
        """Test scanner against curl-7.20.0 rpm with extraction turned off"""
        assert main(["cve-bin-tool", os.path.join(self.tempdir, CURL_7_20_0_RPM)]) != 0

    def test_extract_bad_zip_messages(self, caplog):
        """Test that bad zip files are logged as extraction failed, but
        bad exe files produce no such message"""
        BAD_EXE_FILE = os.path.join(
            os.path.join(os.path.abspath(os.path.dirname(__file__)), "assets"),
            "empty-file.exe",
        )
        with caplog.at_level(logging.WARNING):
            main(["cve-bin-tool", BAD_EXE_FILE])
        assert "Failure extracting" not in caplog.text

        BAD_ZIP_FILE = os.path.join(
            os.path.join(os.path.abspath(os.path.dirname(__file__)), "assets"),
            "empty-file.zip",
        )
        with caplog.at_level(logging.WARNING):
            main(["cve-bin-tool", BAD_ZIP_FILE])
        assert "Failure extracting" in caplog.text

    def test_exclude(self, caplog):
        """Test that the exclude paths are not scanned"""
        test_path = os.path.abspath(os.path.dirname(__file__))
        exclude_path = os.path.join(test_path, "assets/")
        checkers = list(VersionScanner().checkers.keys())
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-e", ",".join(exclude_path)])
        self.check_exclude_log(caplog, exclude_path, checkers)

    def test_usage(self):
        """Test that the usage returns 0"""
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool"])
        assert e.value.args[0] == -6

    def test_invalid_file_or_directory(self):
        """Test behaviour with an invalid file/directory"""
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "non-existant"])
        assert e.value.args[0] == -3

    def test_invalid_parameter(self):
        """Test that invalid parmeters exit with expected error code.
        ArgParse calls sys.exit(2) for all errors, we've overwritten to -2"""

        # no directory specified
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--bad-param"])
        assert e.value.args[0] == -2

        # bad parameter (but good directory)
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--bad-param", self.tempdir])
        assert e.value.args[0] == -2

        # worse parameter
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--bad-param && cat hi", self.tempdir])
        assert e.value.args[0] == -2

        # bad parameter after directory
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", self.tempdir, "--bad-param;cat hi"])
        assert e.value.args[0] == -2

    @unittest.skipUnless(LONG_TESTS() > 0, "Skipping long tests")
    def test_update_flags(self):
        assert main(["cve-bin-tool", "-x", "-u", "never", self.tempdir]) != 0
        assert main(["cve-bin-tool", "-x", "--update", "daily", self.tempdir]) != 0
        assert main(["cve-bin-tool", "-x", "-u", "now", self.tempdir]) != 0
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "-u", "whatever", self.tempdir])
        assert e.value.args[0] == -2

    @staticmethod
    def check_exclude_log(caplog, exclude_path, checkers):
        # The final log has all the checkers detected
        final_log = [
            record for record in caplog.records if "NewFound CVEs" in record.message
        ]
        assert len(final_log) == 0, "Checkers from excluded path scanned!!"
        if final_log:
            final_log = final_log[0].message
            for checker in checkers:
                assert checker in final_log, f"found a CVE {checker} in {exclude_path}"

        caplog.clear()

    @staticmethod
    def check_checkers_log(caplog, skip_checkers, include_checkers):
        # The final log has all the checkers detected
        final_log = [
            record for record in caplog.records if "Checkers:" in record.message
        ]
        assert len(final_log) > 0, "Could not find checkers line in log"
        final_log = final_log[0].message
        for checker in skip_checkers:
            assert checker not in final_log, f"found skipped checker {checker}"

        for checker in include_checkers:
            assert checker in final_log, f"could not find expected checker {checker}"
        caplog.clear()

    def test_skips(self, caplog):
        """Tests the skips option"""

        test_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

        skip_checkers = ["systemd", "xerces", "xml2", "kerberos"]
        include_checkers = ["expat", "libgcrypt", "openssl", "sqlite"]
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-s", ",".join(skip_checkers)])
        self.check_checkers_log(caplog, skip_checkers, include_checkers)

        # swap skip_checkers and include_checkers
        include_checkers, skip_checkers = skip_checkers, include_checkers
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-s", ",".join(skip_checkers)])
        self.check_checkers_log(caplog, skip_checkers, include_checkers)

    def test_runs(self, caplog):
        test_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

        runs = ["expat", "libgcrypt", "openssl", "sqlite"]
        skip_checkers = ["systemd", "xerces", "xml2", "kerberos"]
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-r", ",".join(runs)])
        self.check_checkers_log(caplog, skip_checkers, runs)

        runs, skip_checkers = skip_checkers, runs
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-r", ",".join(runs)])
        self.check_checkers_log(caplog, skip_checkers, runs)

    @unittest.skipUnless(LONG_TESTS() > 0, "Skipping long tests")
    def test_update(self, caplog):
        test_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "csv")

        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", "-u", "never", test_path])
        assert (
            "cve_bin_tool",
            logging.WARNING,
            "Not verifying CVE DB cache",
        ) in caplog.record_tuples
        caplog.clear()

        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", "-u", "daily", test_path])
        assert (
            "cve_bin_tool.CVEDB",
            logging.INFO,
            "Using cached CVE data (<24h old). Use -u now to update immediately.",
        ) in caplog.record_tuples or (
            "cve_bin_tool.CVEDB",
            logging.INFO,
            "Updating CVE data. This will take a few minutes.",
        ) in caplog.record_tuples
        caplog.clear()

        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", "-u", "now", test_path])
        db_path = DISK_LOCATION_DEFAULT
        assert (
            "cve_bin_tool.CVEDB",
            logging.WARNING,
            f"Updating cachedir {db_path}",
        ) in caplog.record_tuples and (
            "cve_bin_tool.CVEDB",
            logging.INFO,
            "Updating CVE data. This will take a few minutes.",
        ) in caplog.record_tuples
        caplog.clear()

        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", "-u", "latest", test_path])
        assert (
            "cve_bin_tool.CVEDB",
            logging.INFO,
            "Updating CVE data. This will take a few minutes.",
        ) in caplog.record_tuples
        caplog.clear()

    def test_unknown_warning(self, caplog):
        """Test that an "UNKNOWN" file generates a warning"""

        # build the unknown test file in test/binaries
        with tempfile.NamedTemporaryFile(
            "w+b", suffix="png-unknown.out", delete=False
        ) as f:
            signatures = [
                b"\x7f\x45\x4c\x46\x02\x01\x01\x03\n",
                b"Application uses deprecated png_write_init() and should be recompiled",
            ]
            f.writelines(signatures)
            filename = f.name

        # Run against the "unknown" file
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", filename])

        # clean up temporary file.
        os.remove(filename)

        warnings = [
            record.message
            for record in caplog.records
            if record.levelname == "WARNING" and record.module == "version_scanner"
        ]
        assert len(warnings) > 0, "Unknown version warning didn't get generated"
        assert f"png was detected with version UNKNOWN in file {filename}" in warnings

    def test_quiet_mode(self, capsys, caplog):
        """Test that an quite mode isn't generating any output"""

        with tempfile.NamedTemporaryFile(
            "w+b", suffix="strong-swan-4.6.3.out", delete=False
        ) as f:
            signatures = [b"\x7f\x45\x4c\x46\x02\x01\x01\x03\n", b"strongSwan 4.6.3"]
            f.writelines(signatures)
            filename = f.name

        main(["cve-bin-tool", "-q", filename, "-u", "now"])
        # clean up temporary file.
        os.remove(filename)

        # Make sure log is empty
        assert not caplog.records

        # Make sure nothing is getting printed on stdout or stderr
        captured = capsys.readouterr()
        assert not (captured.out or captured.err)

    @pytest.mark.parametrize(
        "filename",
        (
            os.path.join(TEST_PATH, "config", "cve_bin_tool_config.toml"),
            os.path.join(TEST_PATH, "config", "cve_bin_tool_config.yaml"),
        ),
    )
    def test_config_file(self, caplog, filename):
        # scan with config file and overwrite output format
        assert main(["cve-bin-tool", "-C", filename, "-l", "info"]) != 0

        # assert only checkers for binutils and curl get to run
        assert (
            "cve_bin_tool.VersionScanner",
            logging.INFO,
            "Checkers: binutils, curl",
        ) in caplog.record_tuples

        # assert only CVEs of curl get reflected. Because other are skipped
        assert (
            "cve_bin_tool",
            logging.INFO,
            "There are 1 products with known CVEs detected",
        ) in caplog.record_tuples

        for record in caplog.record_tuples:
            if record[1] < 20:
                pytest.fail(
                    msg="cli option should override logging level specified in config file"
                )

    @staticmethod
    def check_string_in_file(filename, string_to_find):
        # Check if 'string_to_find' is in file
        fh = open(filename)
        file_contents = fh.readlines()
        fh.close()
        for line in file_contents:
            if string_to_find in line:
                return True
        return False

    def test_severity(self, capsys, caplog):
        # scan with severity setting to ensure only CVEs above severity threshold are reported

        # Check command line parameters - wrong case
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "-S", "HIGH", self.tempdir])
        assert e.value.args[0] == -2
        # Check command line parameters - wrong option
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "-S", "ALL", self.tempdir])
        assert e.value.args[0] == -2

        my_test_filename = "sevtest.csv"

        if os.path.exists(my_test_filename):
            os.remove(my_test_filename)
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    "-S",
                    "high",
                    os.path.join(self.tempdir, CURL_7_20_0_RPM),
                ]
            )
        # Verify that no CVEs with a severity of Medium are reported
        assert not self.check_string_in_file(my_test_filename, "MEDIUM")
        # Verify that CVEs with a higher severity are reported
        assert self.check_string_in_file(my_test_filename, "HIGH")
        caplog.clear()
        if os.path.exists(my_test_filename):
            os.remove(my_test_filename)

    def test_CVSS_score(self, capsys, caplog):
        # scan with severity score to ensure only CVEs above score threshold are reported

        my_test_filename = "sevtest.csv"

        # Check command line parameters. Less than 0 result in default behaviour.
        if os.path.exists(my_test_filename):
            os.remove(my_test_filename)
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "-c",
                    "-1",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    os.path.join(self.tempdir, CURL_7_20_0_RPM),
                ]
            )
        # Verify that some CVEs with a severity of Medium are reported
        assert self.check_string_in_file(my_test_filename, "MEDIUM")
        caplog.clear()

        # Check command line parameters. >10 results in no CVEs being reported (Maximum CVSS score is 10)
        if os.path.exists(my_test_filename):
            os.remove(my_test_filename)
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "-c",
                    "11",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    os.path.join(self.tempdir, CURL_7_20_0_RPM),
                ]
            )
        # Verify that no CVEs are reported (no file is created)
        assert not os.path.exists(my_test_filename)
        caplog.clear()

        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    os.path.join(self.tempdir, CURL_7_20_0_RPM),
                ]
            )
        # Verify that CVEs with a severity of Medium are reported
        assert self.check_string_in_file(my_test_filename, "MEDIUM")
        caplog.clear()
        if os.path.exists(my_test_filename):
            os.remove(my_test_filename)

        # Now check subset
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "-c",
                    "7",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    os.path.join(self.tempdir, CURL_7_20_0_RPM),
                ]
            )
        # Verify that no CVEs with a severity of Medium are reported
        assert not self.check_string_in_file(my_test_filename, "MEDIUM")
        if os.path.exists(my_test_filename):
            os.remove(my_test_filename)
        caplog.clear()
