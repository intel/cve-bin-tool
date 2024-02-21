# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ed

https://www.cvedetails.com/product/1094/GNU-ED.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class EdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)[A-Za-z0-9 '%\.\-\r\n]*GNU ed",
        r"ed\.html[A-Za-z /:\.\r\n]*([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "ed")]
