# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pcre2

https://www.cvedetails.com/product/33513/Pcre-Pcre2.html?vendor_id=3265

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Pcre2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"BSR_UNICODE\)\r?\n([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("pcre", "pcre2")]
