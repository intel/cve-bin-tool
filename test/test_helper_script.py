# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import sys

import pytest

from cve_bin_tool.helper_script import HelperScript, scan_files


class TestHelperScript:
    @pytest.mark.parametrize(
        "filename, product_name, version_name",
        [
            (
                "libsndfile-1.0.25-12.el7.x86_64.rpm",
                "libsndfile",
                "1.0.25",
            ),  # normal packages (with 2 '-')
            (
                "libsndfile-1.0.31-1-aarch64.pkg.tar.xz",
                "libsndfile",
                "1.0.31",
            ),  # .tar.xz packages (with 3 '-')
            (
                "logrotate_3.14.0-4ubuntu5_amd64.deb",
                "logrotate",
                "3.14.0",
            ),  # .deb packages (with 2 '_')
            (
                "libarchive_3.4.2-1_aarch64_cortex-a72.ipk",
                "libarchive",
                "3.4.2",
            ),  # .ipk packages (with 3 '_')
            (
                "tomcat9_9.0.37-3_all.deb",
                "tomcat9",
                "9.0.37",
            ),  # packages with digits in product_name
            (
                "openssh-client_8.4p1-5ubuntu1_amd64.deb",
                "openssh-client",
                "8.4p1",
            ),  # packages with '-' in product_name
            (
                "./Packages/bash-4.2.46-34.el7.x86_64.rpm",
                "bash",
                "4.2.46",
            ),  # directory names
        ],
    )
    def test_parse_filename(self, filename, product_name, version_name):
        hs = HelperScript(filename)
        assert (product_name, version_name) == hs.parse_filename(filename)

    def test_scan_files_no_product(self, caplog):
        args = {
            "filenames": [
                "test/condensed-downloads/dovecot-2.3.14-1.fc34.i686.rpm",
                "test/condensed-downloads/dovecot-core_2.3.13+dfsg1-1ubuntu1_amd64.deb",
            ],
            "product_name": None,
            "version_number": None,
            "string_length": 30,
        }

        with caplog.at_level(logging.ERROR):
            scan_files(args)
            assert "PRODUCT_NAME not in arguments" in caplog.text

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Causing failures in CI on windows"
    )
    def test_scan_files_version(self, caplog):
        args = {
            "filenames": [
                "test/condensed-downloads/dovecot-2.3.14-1.fc34.i686.rpm",
                "test/condensed-downloads/dovecot-core_2.3.13+dfsg1-1ubuntu1_amd64.deb",
            ],
            "product_name": "dovecot",
            "version_number": "2.3.14",
            "string_length": 30,
        }

        with caplog.at_level(logging.WARNING):
            scan_files(args)
            assert (
                "VERSION_NUMBER in arguments, common strings may not be found if files have different versions"
                in caplog.text
            )

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Causing failures in CI on windows"
    )
    def test_scan_files_common(self, capfd):
        args = {
            "filenames": [
                "test/condensed-downloads/dovecot-2.3.14-1.fc34.i686.rpm",
                "test/condensed-downloads/dovecot-core_2.3.13+dfsg1-1ubuntu1_amd64.deb",
            ],
            "product_name": "dovecot",
            "version_number": "2.3.14",
            "string_length": 30,
        }

        scan_files(args)
        out, _ = capfd.readouterr()
        assert "Common CONTAINS_PATTERNS" in out
        assert "FILENAME_PATTERNS" not in out
        assert "VERSION_PATTERNS" not in out
        assert "VENDOR_PRODUCT" not in out

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Causing failures in CI on windows"
    )
    def test_scan_files_single(self, capfd):
        args = {
            "filenames": [
                "test/condensed-downloads/dovecot-2.3.14-1.fc34.i686.rpm",
            ],
            "product_name": "dovecot",
            "version_number": "2.3.14",
            "string_length": 30,
        }

        scan_files(args)
        out, _ = capfd.readouterr()
        assert "CONTAINS_PATTERNS" in out
        assert "FILENAME_PATTERNS" in out
        assert "VERSION_PATTERNS" in out
        assert "VENDOR_PRODUCT" in out

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Causing failures in CI on windows"
    )
    def test_scan_files_multiline(self, capfd):
        args = {
            "filenames": [
                "test/condensed-downloads/dovecot-2.3.14-1.fc34.i686.rpm",
            ],
            "product_name": "dovecot",
            "version_number": "2.3.14",
            "string_length": 30,
        }

        scan_files(args)
        out, _ = capfd.readouterr()
        out = out.split("VERSION_PATTERNS")[1]
        assert "(?:(?:\\r?\\n.*?)*)" not in out

        args = {
            "filenames": [
                "test/condensed-downloads/gnome-shell-41.2-1.fc35.x86_64.rpm",
            ],
            "product_name": "gnome-shell",
            "version_number": "41.2",
            "string_length": 30,
        }

        scan_files(args)
        out, _ = capfd.readouterr()
        out = out.split("VERSION_PATTERNS")[1]
        assert "(?:(?:\\r?\\n.*?)*)" in out

    # @pytest.mark.parametrize("filename", [
    #     "bash-4.2.46-34.el7.x86_64.abc" # unsupported file type
    # ])

    # @pytest.mark.parametrize("filename", [
    #     "bash-4.2.46-34.el7.x86_64.abc" # unsupported file type
    # ])
    # def test_parse_filename(self, filename):
    #     hs = HelperScript(filename)
    #     with pytest.raises(UnknownArchiveType):
    #         hs.parse_filename(filename)
