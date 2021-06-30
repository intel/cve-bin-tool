# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
from os import environ
from os.path import dirname, join
from sys import platform

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
            "default": {"remarks": Remarks.Unexplored, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="python*", product="requests", version="2.25.1"): {
            "default": {"remarks": Remarks.Unexplored, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="html5lib*", product="html5lib", version="0.99"): {
            "default": {"remarks": Remarks.Unexplored, "comments": "", "severity": ""},
            "paths": {""},
        },
    }

    UBUNTU_PARSED_TRIAGE_DATA = {
        ProductInfo(vendor="gnu*", product="bash", version="5.0-6ubuntu1.1"): {
            "default": {"remarks": Remarks.Unexplored, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="gnu*", product="binutils", version="2.34-6ubuntu1.1"): {
            "default": {"remarks": Remarks.Unexplored, "comments": "", "severity": ""},
            "paths": {""},
        },
        ProductInfo(vendor="gnu*", product="wget", version="1.20.3-1ubuntu1"): {
            "default": {"remarks": Remarks.Unexplored, "comments": "", "severity": ""},
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
        "filepath, exception",
        [(join(TXT_PATH, "test_broken_linux_list.txt"), InvalidListError)],
    )
    def test_invalid_linux_list(self, filepath, exception):
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        with pytest.raises(exception):
            package_list.parse_list()

    @pytest.mark.skipif(
        "ACTIONS" not in environ
        or not platform == "linux"
        or ("ubuntu" not in distro.id() and "20.04" not in distro.version()),
        reason="Running locally requires root permission",
    )
    @pytest.mark.parametrize(
        "filepath, parsed_data",
        [(join(TXT_PATH, "test_ubuntu_list.txt"), UBUNTU_PARSED_TRIAGE_DATA)],
    )
    def test_valid_ubuntu_list(self, filepath, parsed_data):
        subprocess.run(
            [
                "sudo",
                "apt-get",
                "install",
                "bash=5.0-6ubuntu1.1",
                "binutils=2.34-6ubuntu1.1",
                "wget=1.20.3-1ubuntu1",
            ]
        )
        package_list = PackageListParser(filepath, error_mode=ErrorMode.FullTrace)
        assert package_list.parse_list() == parsed_data
