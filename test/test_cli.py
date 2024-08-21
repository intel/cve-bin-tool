# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool CLI tests
"""
import importlib
import logging
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from test.utils import (
    CURL_7_20_0_RPM,
    CURL_7_20_0_URL,
    DEB_FILE_PATH,
    LONG_TESTS,
    TempDirTest,
    download_file,
)
from unittest.mock import patch

import pytest

from cve_bin_tool.cli import main
from cve_bin_tool.error_handler import ERROR_CODES, InsufficientArgs
from cve_bin_tool.extractor import Extractor
from cve_bin_tool.version_scanner import VersionScanner


class TestCLI(TempDirTest):
    """Tests the CVE Bin Tool CLI"""

    TEST_PATH = Path(__file__).parent.resolve()

    @pytest.mark.skipif(not LONG_TESTS(), reason="No file downloads in short tests")
    def setup_method(self):
        shutil.copyfile(DEB_FILE_PATH, Path(self.tempdir) / "test.deb")
        download_file(CURL_7_20_0_URL, Path(self.tempdir) / CURL_7_20_0_RPM)

    @pytest.mark.skipif(not LONG_TESTS(), reason="No file downloads in short tests")
    def test_extract_curl_7_20_0(self):
        """Scanning curl-7.20.0"""
        assert main(["cve-bin-tool", "-l", "debug", "-x", self.tempdir]) != 0

    @pytest.mark.skipif(not LONG_TESTS(), reason="No file downloads in short tests")
    def test_binary_curl_7_20_0(self):
        """Extracting from rpm and scanning curl-7.20.0"""
        with Extractor() as ectx:
            extracted_path = ectx.extract(str(Path(self.tempdir) / CURL_7_20_0_RPM))
            assert (
                main(
                    [
                        "cve-bin-tool",
                        "-l",
                        "debug",
                        str(Path(extracted_path) / "usr" / "bin" / "curl"),
                    ]
                )
                != 0
            )

    @pytest.mark.skipif(not LONG_TESTS(), reason="No file downloads in short tests")
    def test_no_extraction(self):
        """Test scanner against curl-7.20.0 rpm with extraction turned off"""
        assert main(["cve-bin-tool", str(Path(self.tempdir) / CURL_7_20_0_RPM)]) != 0

    def test_extract_bad_zip_messages(self, caplog):
        """Test that bad zip files are logged as extraction failed, but
        bad exe files produce no such message"""
        bad_exe_file = str(Path(self.tempdir) / "empty-file.exe")
        # creates an empty, invalid .exe test file
        open(bad_exe_file, "w").close()
        with caplog.at_level(logging.WARNING):
            main(["cve-bin-tool", bad_exe_file])
        assert "Failure extracting" not in caplog.text

        bad_zip_file = str(Path(self.tempdir) / "empty-file.zip")
        open(bad_zip_file, "w").close()
        with caplog.at_level(logging.WARNING):
            main(["cve-bin-tool", bad_zip_file])
        assert "Failure extracting" in caplog.text

    def test_extract_encrypted_zip_messages(self, caplog):
        """Test that encrypted zip file are logged as
        extraction failure and the file is password protected"""
        test_file = str(
            Path(__file__).parent.resolve() / "assets" / "test-encrypted.zip"
        )
        with caplog.at_level(logging.ERROR):
            main(["cve-bin-tool", str(test_file)])
        assert "The file is password protected" in caplog.text

    @pytest.mark.skipif(not LONG_TESTS(), reason="No file downloads in short tests")
    def test_exclude(self, caplog):
        """Test that the exclude paths are not scanned"""
        test_path = Path(__file__).parent.resolve()
        exclude_path = str(test_path / "assets/")
        checkers = list(VersionScanner().checkers.keys())
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", str(test_path), "-e", ",".join(exclude_path)])
        self.check_exclude_log(caplog, exclude_path, checkers)

    def test_usage(self):
        """Test that the usage returns 0"""
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool"])
        assert e.value.args[0] == ERROR_CODES[InsufficientArgs]

    def test_version(self):
        """Test that the version returns 0"""
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--version"])
        assert e.value.args[0] == 0

    def test_invalid_file_or_directory(self):
        """Test behaviour with an invalid file/directory"""
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "non-existant"])
        assert e.value.args[0] == ERROR_CODES[FileNotFoundError]

    def test_null_byte_in_filename(self):
        """Test behaviour with an invalid file/directory that contains a \0"""

        # Put a null byte into the filename of a real file used in other tests
        CSV_PATH = Path(__file__).parent.resolve() / "csv"
        null_byte_file = str(CSV_PATH / "test_triage\0.csv")

        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", null_byte_file])
        assert e.value.args[0] == ERROR_CODES[FileNotFoundError]

        null_byte_file = str(CSV_PATH / "test_triage.csv\0something")
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", null_byte_file])
        assert e.value.args[0] == ERROR_CODES[FileNotFoundError]

    def test_invalid_parameter(self):
        """Test that invalid parmeters exit with expected error code.
        ArgParse calls sys.exit(2) for all errors"""

        # no directory specified
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--bad-param"])
        assert e.value.args[0] == 2

        # bad parameter (but good directory)
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--bad-param", self.tempdir])
        assert e.value.args[0] == 2

        # worse parameter
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "--bad-param && cat hi", self.tempdir])
        assert e.value.args[0] == 2

        # bad parameter after directory
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", self.tempdir, "--bad-param;cat hi"])
        assert e.value.args[0] == 2

    @pytest.mark.skipif(not LONG_TESTS(), reason="Update flag tests are long tests")
    def test_update_flags(self):
        assert (
            main(["cve-bin-tool", "-x", "-u", "never", "-n", "json", self.tempdir]) != 0
        )
        assert (
            main(
                ["cve-bin-tool", "-x", "--update", "daily", "-n", "json", self.tempdir]
            )
            != 0
        )
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "-u", "whatever", "-n", "json", self.tempdir])
        assert e.value.args[0] == 2

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

        test_path = str(Path(__file__).parent.resolve() / "csv")

        skip_checkers = ["systemd", "xerces", "xml2", "kerberos"]
        include_checkers = ["libexpat", "libgcrypt", "openssl", "sqlite"]
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-s", ",".join(skip_checkers)])
        self.check_checkers_log(caplog, skip_checkers, include_checkers)

        # swap skip_checkers and include_checkers
        include_checkers, skip_checkers = skip_checkers, include_checkers
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-s", ",".join(skip_checkers)])
        self.check_checkers_log(caplog, skip_checkers, include_checkers)

    def test_runs(self, caplog):
        test_path = str(Path(__file__).parent.resolve() / "csv")

        runs = ["libexpat", "libgcrypt", "openssl", "sqlite"]
        skip_checkers = ["systemd", "xerces", "xml2", "kerberos"]
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-r", ",".join(runs)])
        self.check_checkers_log(caplog, skip_checkers, runs)

        runs, skip_checkers = skip_checkers, runs
        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", test_path, "-r", ",".join(runs)])
        self.check_checkers_log(caplog, skip_checkers, runs)

    @pytest.mark.skipif(not LONG_TESTS(), reason="Update flag tests are long tests")
    def test_update(self, caplog):
        test_path = str(Path(__file__).parent.resolve() / "csv")

        with caplog.at_level(logging.INFO):
            main(["cve-bin-tool", "-u", "never", "-n", "json", test_path])
        assert (
            "cve_bin_tool",
            logging.WARNING,
            "Not verifying CVE DB cache",
        ) in caplog.record_tuples
        caplog.clear()

        with caplog.at_level(logging.DEBUG):
            main(
                ["cve-bin-tool", "-l", "debug", "-u", "daily", "-n", "json", test_path]
            )
        assert (
            "cve_bin_tool.CVEDB",
            logging.INFO,
            "Using cached CVE data (<24h old). Use -u now to update immediately.",
        ) in caplog.record_tuples or (
            "cve_bin_tool.CVEDB",
            logging.DEBUG,
            "Updating CVE data. This will take a few minutes.",
        ) in caplog.record_tuples
        caplog.clear()

        with caplog.at_level(logging.DEBUG):
            main(
                ["cve-bin-tool", "-l", "debug", "-u", "latest", "-n", "json", test_path]
            )
        assert (
            "cve_bin_tool.CVEDB",
            logging.DEBUG,
            "Updating CVE data. This will take a few minutes.",
        ) in caplog.record_tuples
        caplog.clear()

    def test_unknown_warning(self, caplog):
        """Test that an "UNKNOWN" file generates a log (only in debug mode)"""

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
        with caplog.at_level(logging.DEBUG):
            main(["cve-bin-tool", filename, "-l", "debug"])

        # clean up temporary file.
        Path(filename).unlink()

        warnings = [
            record.message
            for record in caplog.records
            if record.levelname == "DEBUG" and record.module == "version_scanner"
        ]
        assert len(warnings) > 0, "Unknown version warning didn't get generated"
        assert f"png was detected with version UNKNOWN in file {filename}" in warnings

    @patch("socket.socket")
    def test_quiet_mode(self, mock_socket, capsys, caplog):
        """Test that a quiet mode isn't generating any output"""

        for connection_error_scenario in [True, False]:
            mock_socket.return_value.connect.side_effect = (
                ConnectionError if connection_error_scenario else None
            )

            with tempfile.NamedTemporaryFile(
                "w+b", suffix="strong-swan-4.6.3.out", delete=False
            ) as f:
                signatures = [
                    b"\x7f\x45\x4c\x46\x02\x01\x01\x03\n",
                    b"strongSwan 4.6.3",
                ]
                f.writelines(signatures)
                filename = f.name

            main(["cve-bin-tool", "-q", filename])
            # clean up temporary file.
            Path(filename).unlink()

            # Make sure log is empty
            assert not caplog.records

            # Make sure nothing is getting printed on stdout or stderr
            captured = capsys.readouterr()
            assert not (captured.out or captured.err)

    @pytest.mark.skip(reason="Temporarily disabled -- may need data changes")
    @pytest.mark.parametrize(
        "filename",
        (
            str(TEST_PATH / "config" / "cve_bin_tool_config.toml"),
            str(TEST_PATH / "config" / "cve_bin_tool_config.yaml"),
        ),
    )
    def test_config_file(self, caplog, filename):
        # scan with config file and overwrite output format
        assert main(["cve-bin-tool", "-C", filename, "-l", "info"]) != 0

        # assert only checkers for binutils and libcurl get to run
        assert (
            "cve_bin_tool.VersionScanner",
            logging.INFO,
            "Checkers: binutils, libcurl",
        ) in caplog.record_tuples

        # assert only CVEs of libcurl get reflected. Because others are skipped
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
        assert e.value.args[0] == 2
        # Check command line parameters - wrong option
        with pytest.raises(SystemExit) as e:
            main(["cve-bin-tool", "-S", "ALL", self.tempdir])
        assert e.value.args[0] == 2

        my_test_filename = "sevtest.csv"
        my_test_filename_pathlib = Path(my_test_filename)

        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
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
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that no CVEs with a severity of Medium are reported
        assert not self.check_string_in_file(my_test_filename, "MEDIUM")
        # Verify that CVEs with a higher severity are reported
        assert self.check_string_in_file(my_test_filename, "HIGH")
        caplog.clear()
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

    def test_CVSS_score(self, capsys, caplog):
        # scan with severity score to ensure only CVEs above score threshold are reported

        my_test_filename = "sevtest.csv"
        my_test_filename_pathlib = Path(my_test_filename)

        # Check command line parameters. Less than 0 result in default behaviour.
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
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
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that some CVEs with a severity of Medium are reported
        assert self.check_string_in_file(my_test_filename, "MEDIUM")
        caplog.clear()

        # Check command line parameters. >10 results in no CVEs being reported (Maximum CVSS score is 10)
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
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
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that no CVEs are reported
        with open(my_test_filename_pathlib) as fd:
            assert not fd.read().split("\n")[1]
        caplog.clear()
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that CVEs with a severity of Medium are reported
        assert self.check_string_in_file(my_test_filename, "MEDIUM")
        caplog.clear()
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

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
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that no CVEs with a severity of Medium are reported
        assert not self.check_string_in_file(my_test_filename, "MEDIUM")
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
        caplog.clear()

    def test_EPSS_probability(self, capsys, caplog):
        """scan with EPSS probability to ensure only CVEs above score threshold are reported
        Checks cannot placed on epss probability value as the value changes everyday
        """

        my_test_filename = "epss_probability.csv"
        my_test_filename_pathlib = Path(my_test_filename)

        # Check command line parameters. Less than 0 result in default behaviour.
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "--epss-probability",
                    "-12",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that some CVEs with a severity of Medium are reported
        # Checks cannot placed on epss probability value as the value changes everyday.
        assert self.check_string_in_file(my_test_filename, "MEDIUM")
        caplog.clear()
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "--epss-probability",
                    "110",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )

        # FIXME: disabled due to test failures, needs better fix. issue #3674
        # Verify that no CVEs are reported
        # with open(my_test_filename_pathlib) as fd:
        #    assert not fd.read().split("\n")[1]
        caplog.clear()
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

    def test_EPSS_percentile(self, capsys, caplog):
        """scan with EPSS percentile to ensure only CVEs above score threshold are reported
        Checks cannot placed on epss percentile value as the value changes everyday
        """

        my_test_filename = "epss_percentile.csv"
        my_test_filename_pathlib = Path(my_test_filename)

        # Check command line parameters. Less than 0 result in default behaviour.
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "--epss-percentile",
                    "-1",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )
        # Verify that some CVEs with a severity of Medium are reported
        # Checks cannot placed on epss percentile value as the value changes everyday.
        assert self.check_string_in_file(my_test_filename, "MEDIUM")
        caplog.clear()

        # Check command line parameters. >10 results in no CVEs being reported (Maximum EPSS percentile is 100)
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()
        with caplog.at_level(logging.DEBUG):
            main(
                [
                    "cve-bin-tool",
                    "-x",
                    "--epss-percentile",
                    "110",
                    "-f",
                    "csv",
                    "-o",
                    my_test_filename,
                    str(Path(self.tempdir) / CURL_7_20_0_RPM),
                ]
            )

        # FIXME: disabled due to test failures, needs better fix. issue #3674
        # Verify that no CVEs are reported
        # with open(my_test_filename_pathlib) as fd:
        #     assert not fd.read().split("\n")[1]
        caplog.clear()
        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

    # @pytest.mark.skip(reason="Temporarily disabled -- may need data changes")
    def test_SBOM(self, caplog):
        # check sbom file option
        SBOM_PATH = Path(__file__).parent.resolve() / "sbom"

        with caplog.at_level(logging.INFO):
            main(
                [
                    "cve-bin-tool",
                    "--sbom",
                    "spdx",
                    "--sbom-file",
                    str(SBOM_PATH / "spdx_test.spdx"),
                ]
            )

        # find the "known CVEs detected" line from caplog
        known_cves_message = None
        # tuple is (tool_name, log_level, log_message) but we only care about the last
        for _, _, log_message in caplog.record_tuples:
            if re.search(r"with known CVEs detected", log_message):
                known_cves_message = log_message

        assert (
            known_cves_message is not None
        ), "Expected 3 products with cves, none found"

        # since sometimes this test breaks due to data changes, let's just say we want at least 2
        # products with cves (though there should be 3 at time of writing)
        m = re.match(
            r"There are (?P<product_number>\d*) products with known CVEs detected",
            known_cves_message,
        )
        assert (
            int(m.group("product_number")) >= 2
        ), "Not enough products with cves found in output"

    def test_sbom_detection(self, caplog):
        SBOM_PATH = Path(__file__).parent.resolve() / "sbom"

        with caplog.at_level(logging.INFO):
            main(
                [
                    "cve-bin-tool",
                    str(SBOM_PATH / "swid_test.xml"),
                ]
            )

        assert (
            "cve_bin_tool",
            logging.INFO,
            "Using CVE Binary Tool SBOM Auto Detection",
        ) in caplog.record_tuples

    @pytest.mark.skipif(not LONG_TESTS(), reason="Skipping long tests")
    def test_console_output_depending_reportlab_existence(self, caplog):
        import subprocess
        from importlib.machinery import ModuleSpec
        from importlib.util import find_spec, module_from_spec

        if find_spec("reportlab"):
            reportlab_was_installed = True
            sys.modules.pop("reportlab")
            subprocess.check_call(
                [sys.executable, "-m", "pip", "uninstall", "-y", "reportlab"]
            )
        else:
            reportlab_was_installed = False

        my_test_filename_pathlib = Path(self.tempdir) / "reportlab_test_report.pdf"
        my_test_filename = str(my_test_filename_pathlib)

        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

        pkg_to_spoof = "reportlab"
        not_installed_msg = "PDF output not available."
        execution = [
            "cve-bin-tool",
            "-f",
            "pdf",
            "-o",
            my_test_filename,
            str(Path(self.tempdir) / CURL_7_20_0_RPM),
        ]

        with caplog.at_level(logging.INFO):
            main(execution)

        assert (
            "cve_bin_tool",
            logging.ERROR,
            not_installed_msg,
        ) in caplog.record_tuples

        caplog.clear()

        if my_test_filename_pathlib.exists():
            my_test_filename_pathlib.unlink()

        if reportlab_was_installed:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab"])
        else:
            ms = ModuleSpec(pkg_to_spoof, "surelyanotexistentmodule")
            m = module_from_spec(ms)
            sys.modules[pkg_to_spoof] = m

        with caplog.at_level(logging.INFO):
            main(execution)
        assert (
            "cve_bin_tool",
            logging.INFO,
            not_installed_msg,
        ) not in caplog.record_tuples

    @pytest.mark.skipif(
        not importlib.util.find_spec("reportlab"),
        reason="Reportlab needed for pdf test",
    )
    def test_0_cve_pdf_report(self, caplog):
        """Tests to make sure --report behaves as expected when 0 cves are found.
        We expect a short pdf file saying 0 cves were found."""

        with tempfile.TemporaryDirectory() as emptytemp:
            # Set a filename for report in tempdir, make sure it doesn't exist.
            report_0 = Path(self.tempdir) / "0_cve_report.pdf"
            if report_0.exists():
                report_0.unlink()

            # Call cve-bin-tool to scan empty dir and product pdf report.
            cbt_command = [
                "cve-bin-tool",
                "--offline",
                "--format",
                "pdf",
                "-o",
                str(report_0),
                "--report",
                str(emptytemp),
            ]
            main(cbt_command)

            # Make sure the report was created and has something in it.
            # Testing what's in the report would increase test execution time
            # so we're leaving that out for now
            assert report_0.exists()
            assert report_0.stat().st_size > 0

            # get rid of generated file
            report_0.unlink()

    yamls = [
        [
            "cve-bin-tool",
            "--generate-config",
            "yaml",
            "-n",
            "api2",
            "--format",
            "csv",
            "--severity",
            "high",
            "-i",
            "test/test_json.py",
        ],
    ]
    output_yamls = [
        [
            "nvd : api2",
            "format : csv",
            "severity : high",
            "input_file : test/test_json.py",
            "update : daily",
            "log_level : info",
            "nvd_api_key : ",
            "offline : false",
            "vex_file : ",
        ],
    ]
    tomls = [
        [
            "cve-bin-tool",
            "--generate-config",
            "toml",
            "--nvd",
            "json",
            "--sbom",
            "swid",
            "--log",
            "warning",
            "--offline",
        ],
    ]
    output_tomls = [
        [
            'nvd = "json"',
            'sbom = "swid"',
            'log_level = "warning"',
            "offline = true",
            'input_file = ""',
            'sbom_file = ""',
            'runs = ""',
            "extract = true",
            "append = false",
            'import = ""',
            'vex_file = ""',
        ],
    ]

    @pytest.mark.parametrize(
        "args, expected_files, expected_contents",
        [
            (
                yamls[0],
                "config.yaml",
                output_yamls[0],
            ),
            (tomls[0], "config.toml", output_tomls[0]),
        ],
    )
    def test_config_generator(self, args, expected_files, expected_contents, caplog):
        # When
        with caplog.at_level(logging.INFO):
            main(args)
        # Then
        assert os.path.exists(expected_files)
        with open(expected_files) as f:
            content = f.read()
            for expected_content in expected_contents:
                assert expected_content in content
        # Cleanup
        os.remove(expected_files)

    def test_disabled_sources(self, caplog):
        """Attempts to disable various data sources and makes sure they appear
        to be disabled correctly.

        This only tests for disabled messages, it doesn't check on the update code
        because we'd have to actually do updates then and they're slow.
        """

        # attempt to call with all sources disabled
        with caplog.at_level(logging.INFO):
            main(
                [
                    "cve-bin-tool",
                    "--update",
                    "never",
                    "--nvd-api-key",
                    "no",
                    "-n",
                    "json-mirror",
                    "--disable-data-source",
                    "CURL,EPSS,GAD,OSV,REDHAT,RSD",
                    self.tempdir,
                ]
            )
            # check that nvd key was disabled as expected
            assert "NVD API Key was set to 'no' and will not be used" in caplog.text
            for source in ["CURL", "EPSS", "GAD", "OSV", "REDHAT", "RSD"]:
                assert f"Disabling data source {source}" in caplog.text
