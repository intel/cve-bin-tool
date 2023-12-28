# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lrzip

https://www.cvedetails.com/product/43040/Long-Range-Zip-Project-Long-Range-Zip.html?vendor_id=17530

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LrzipChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"lrz%s version %s\r?\n([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+)\r?\nlrz%s version %s",
    ]
    VENDOR_PRODUCT = [("long_range_zip_project", "long_range_zip")]
