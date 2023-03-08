# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for squid

https://www.cvedetails.com/product/1814/Squid-Squid.html?vendor_id=823
https://www.cvedetails.com/product/17766/Squid-cache-Squid.html?vendor_id=9950

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SquidChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"squid/([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("squid", "squid"), ("squid-cache", "squid")]
