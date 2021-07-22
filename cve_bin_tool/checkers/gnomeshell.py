# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for gnome-shell

https://www.cvedetails.com/product/20202/?q=Gnome-shell
"""
from cve_bin_tool.checkers import Checker


class GnomeshellChecker(Checker):
    CONTAINS_PATTERNS = [
        r"\* Creates a window using gnome-shell-perf-helper for testing purposes."
    ]
    FILENAME_PATTERNS = [r"gnome-shell"]
    VERSION_PATTERNS = [
        r"var PACKAGE_NAME = 'gnome\-shell';\r?\n/\* The version of this package \*/\r?\nvar PACKAGE_VERSION = '([0-9]+\.[0-9]+(\.[0-9]+)?)';"
    ]
    VENDOR_PRODUCT = [("gnome", "gnome-shell")]
