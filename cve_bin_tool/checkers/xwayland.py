# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for xwayland

https://www.cvedetails.com/product/163618/X.org-Xwayland.html?vendor_id=88

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class XwaylandChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z. \r\n]*%s Xwayland"]
    VENDOR_PRODUCT = [("x.org", "xwayland")]
