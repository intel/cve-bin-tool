# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
from pathlib import Path

import distro
import pytest

from cve_bin_tool.error_handler import ErrorMode
from cve_bin_tool.package_list_parser import (
    SUPPORTED_DISTROS,
    EmptyTxtError,
    InvalidListError,
    PackageListParser,
    Remarks,
)
from cve_bin_tool.util import ProductInfo


class TestPackageListParser:
    """
    Tests for cve_bin_tool/package_list_parser.py
    It handles parsing of package data on specific linux distros.
    """

    TXT_PATH = Path(__file__).parent.resolve() / "txt"

    REQ_PARSED_TRIAGE_DATA = {
        ProductInfo(
            vendor="httplib2_project*",
            product="httplib2",
            version="0.18.1",
            location="/usr/local/bin/httplib2",
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(
            vendor="python*",
            product="requests",
            version="2.25.1",
            location="/usr/local/bin/requests",
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
    }

    # Find the versions of the ubuntu packages
    UBUNTU_PACKAGE_VERSIONS = (
        (
            subprocess.run(
                [
                    "dpkg-query",
                    "--show",
                    "--showformat=${Version}\n",
                    "bash",
                    "binutils",
                    "wget",
                ],
                stdout=subprocess.PIPE,
            )
            .stdout.decode("utf-8")
            .splitlines()
        )
        if "ubuntu" in distro.id()
        else ["dummy", "array", "for windows"]
    )

    UBUNTU_PARSED_TRIAGE_DATA = {
        ProductInfo(
            vendor="gnu*",
            product="bash",
            version=UBUNTU_PACKAGE_VERSIONS[0],
            location="/usr/local/bin/bash",
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(
            vendor="gnu*",
            product="binutils",
            version=UBUNTU_PACKAGE_VERSIONS[1],
            location="/usr/local/bin/binutils",
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(
            vendor="gnu*",
            product="wget",
            version=UBUNTU_PACKAGE_VERSIONS[2],
            location="/usr/local/bin/wget",
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
    }

    @pytest.mark.parametrize("filepath", [str(TXT_PATH / "nonexistent.txt")])
    def test_nonexistent_txt(self, filepath):
        """Test behaviour on non-existent file"""
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(FileNotFoundError):
            package_list.parse_list()

    @pytest.mark.parametrize(
        "filepath, exception", [(str(TXT_PATH / "empty.txt"), EmptyTxtError)]
    )
    def test_empty_txt(self, filepath, exception):
        """Test an empty list"""
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(exception):
            package_list.parse_list()

    @pytest.mark.parametrize(
        "filepath, exception", [(str(TXT_PATH / "not_txt.csv"), InvalidListError)]
    )
    def test_not_txt(self, filepath, exception):
        """Test an invalid type of list"""
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(exception):
            package_list.parse_list()

    # @pytest.mark.skipif(
    #     "ubuntu" not in distro.id(),
    #     reason="Test for Ubuntu systems",
    # )
    @pytest.mark.skip(reason="Test is broken, needs fixing")
    @pytest.mark.parametrize(
        "filepath, parsed_data",
        [(str(TXT_PATH / "test_requirements.txt"), REQ_PARSED_TRIAGE_DATA)],
    )
    def test_valid_requirements(self, filepath, parsed_data):
        """Test a valid requirements list"""
        # packages is installed from test_requirements with specific versions for the test to pass
        subprocess.run(["pip", "install", "-r", filepath])
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        assert package_list.parse_list() == parsed_data
        # Update the packages back to latest
        subprocess.run(["pip", "install", "httplib2", "requests", "-U"])

    @pytest.mark.skipif(
        distro.id() not in SUPPORTED_DISTROS,
        reason=f"Test for {','.join(SUPPORTED_DISTROS)} systems",
    )
    @pytest.mark.parametrize(
        "filepath",
        [str(TXT_PATH / "test_broken_linux_list.txt")],
    )
    def test_invalid_linux_list(self, filepath, caplog):
        """Test a linux package list with an invalid package"""
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        package_list.check_file()
        expected_output = ["Invalid Package found: br0s"]

        assert expected_output == [rec.message for rec in caplog.records]

    @pytest.mark.skip(reason="Temporarily broken by data changes")
    # @pytest.mark.skipif(
    #     "ubuntu" not in distro.id(),
    #     reason="Test for Ubuntu systems",
    # )
    @pytest.mark.parametrize(
        "filepath, parsed_data",
        [(str(TXT_PATH / "test_ubuntu_list.txt"), UBUNTU_PARSED_TRIAGE_DATA)],
    )
    def test_valid_ubuntu_list(self, filepath, parsed_data):
        """Test a valid ubuntu package list"""
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        assert package_list.parse_list() == parsed_data

    @pytest.mark.skipif(
        distro.id() in SUPPORTED_DISTROS,
        reason="Test for unsupported distros",
    )
    @pytest.mark.parametrize(
        "filepath",
        [str(TXT_PATH / "test_ubuntu_list.txt")],
    )
    def test_unsupported_distros(self, filepath, caplog):
        """Test against a list of packages from an unsupported distro"""
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        expected_output = [
            f"Package list support only available for {','.join(SUPPORTED_DISTROS)}!"
        ]

        with pytest.raises(InvalidListError):
            package_list.parse_list()
            assert expected_output == [rec.message for rec in caplog.records]
