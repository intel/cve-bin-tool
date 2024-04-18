# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool util tests
"""
import inspect
import sys
from pathlib import Path
from typing import DefaultDict

import pytest

from cve_bin_tool.cve_scanner import CVEScanner
from cve_bin_tool.util import CVEData, ProductInfo, find_product_location, inpath


class TestUtil:
    """Test the util functions"""

    def test_inpath(self):
        """Test the check to see if a command line utility is installed
        and in path before we try to run it."""
        assert inpath("python")

    def test_not_inpath(self):
        assert not inpath("cve_bin_tool_test_for_not_in_path")

    @pytest.mark.parametrize(
        "mock_sys_path, known_dirs",
        [
            (
                ["/usr/local/bin", "/usr/local/lib/python3.10/site-packages"],
                [
                    "/usr/local/lib/python3.10/site-packages",
                    "/usr/local/share",
                    "/usr/share",
                    "/usr/local/include",
                    "/usr/include",
                ],
            ),
        ],
    )
    def test_find_product_location(self, monkeypatch, mock_sys_path, known_dirs):
        product_name = "lib4sbom"
        monkeypatch.setattr(sys, "path", mock_sys_path)

        def mock_exists(path):
            for dir in known_dirs:
                if dir in str(path):
                    return True
            return False

        monkeypatch.setattr("pathlib.Path.exists", mock_exists)

        expected_path = None
        for dir in known_dirs:
            product_location = Path(dir) / product_name
            if product_location.exists():
                expected_path = str(product_location)
                break

        assert find_product_location(product_name) == expected_path


class TestSignature:
    """Tests signature of critical class and functions"""

    def test_cve_scanner(self):
        sig = inspect.signature(CVEScanner.get_cves)
        expected_args = {"product_info", "triage_data", "self"}
        assert (
            set(sig.parameters) - expected_args == set()
        ), "Parameters of get_cves has been changed. Make sure it isn't breaking InputEngine!"

        instance_attrs = vars(CVEScanner)["__annotations__"]
        assert (
            instance_attrs["all_cve_data"] == DefaultDict[ProductInfo, CVEData]
        ), "Type of all_cve_data has been changed. Make sure it isn't breaking OutputEngine!"
