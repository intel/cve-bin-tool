# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
from os.path import dirname, join

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
    TXT_PATH = join(dirname(__file__), "txt")

    REQ_PARSED_TRIAGE_DATA = {
        ProductInfo(vendor="httplib2_project*", product="httplib2", version="0.18.1"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="python*", product="requests", version="2.25.1"): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="html5lib*", product="html5lib", version="0.99"): {
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
            vendor="gnu*", product="bash", version=UBUNTU_PACKAGE_VERSIONS[0]
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(
            vendor="gnu*", product="binutils", version=UBUNTU_PACKAGE_VERSIONS[1]
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(
            vendor="gnu*", product="wget", version=UBUNTU_PACKAGE_VERSIONS[2]
        ): {
            "default": {"remarks": Remarks.NewFound, "comments": "", "severity": ""},
            "paths": {""},
        },
    }

    @pytest.mark.parametrize("filepath", [join(TXT_PATH, "nonexistent.txt")])
    def test_nonexistent_txt(self, filepath):
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(FileNotFoundError):
            package_list.parse_list()

    @pytest.mark.parametrize(
        "filepath, exception", [(join(TXT_PATH, "empty.txt"), EmptyTxtError)]
    )
    def test_empty_txt(self, filepath, exception):
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(exception):
            package_list.parse_list()

    @pytest.mark.parametrize(
        "filepath, exception", [(join(TXT_PATH, "not_txt.csv"), InvalidListError)]
    )
    def test_not_txt(self, filepath, exception):
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(exception):
            package_list.parse_list()

    @pytest.mark.parametrize(
        "filepath, parsed_data",
        [(join(TXT_PATH, "test_requirements.txt"), REQ_PARSED_TRIAGE_DATA)],
    )
    def test_valid_requirements(self, filepath, parsed_data):
        # packages is installed from test_requirements with specific versions for the test to pass
        subprocess.run(["pip", "install", "-r", filepath])
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        assert package_list.parse_list() == parsed_data
        # Update the packages back to latest
        subprocess.run(["pip", "install", "httplib2", "requests", "html5lib", "-U"])

    @pytest.mark.skipif(
        distro.id() not in SUPPORTED_DISTROS,
        reason=f"Test for {','.join(SUPPORTED_DISTROS)} systems",
    )
    @pytest.mark.parametrize(
        "filepath",
        [(join(TXT_PATH, "test_broken_linux_list.txt"))],
    )
    def test_invalid_linux_list(self, filepath, caplog):
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        package_list.check_file()
        expected_output = ["Invalid Package found: br0s"]

        assert expected_output == [rec.message for rec in caplog.records]

    @pytest.mark.skipif(
        "ubuntu" not in distro.id(),
        reason="Test for Ubuntu systems",
    )
    @pytest.mark.parametrize(
        "filepath, parsed_data",
        [(join(TXT_PATH, "test_ubuntu_list.txt"), UBUNTU_PARSED_TRIAGE_DATA)],
    )
    def test_valid_ubuntu_list(self, filepath, parsed_data):
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        assert package_list.parse_list() == parsed_data
