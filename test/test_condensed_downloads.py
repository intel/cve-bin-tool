# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Test to check if condensed downloads are committed
"""
import importlib
import subprocess

from cve_bin_tool.checkers import __all__ as all_test_name
from cve_bin_tool.util import windows_fixup


# Test to check condensed files are committed according to the package test data of checkers
def test_condensed_downloads():
    test_data = list(
        map(lambda x: importlib.import_module(f"test.test_data.{x}"), all_test_name[2:])
    )

    package_names = []
    package_test_data_list = map(lambda x: x.package_test_data, test_data)
    for package_test_data in package_test_data_list:
        for package_data in package_test_data:
            package_names.append(
                "test/condensed-downloads/"
                + windows_fixup(package_data["package_name"])
                + ".tar.gz"
            )

    condensed_downloads = subprocess.run(
        ["git", "ls-files", "test/condensed-downloads"],
        stdout=subprocess.PIPE,
    )

    condensed_downloads = condensed_downloads.stdout.decode("utf-8")

    assert all(
        item in condensed_downloads for item in package_names
    ), "Condensed downloads are not commited"
