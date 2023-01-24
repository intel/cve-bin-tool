# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for snort

https://www.cvedetails.com/product/1068/Snort-Snort.html?vendor_id=621
https://www.cvedetails.com/product/1831/Martin-Roesch-Snort.html?vendor_id=1056
https://www.cvedetails.com/product/2893/Sourcefire-Snort.html?vendor_id=1674


"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SnortChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"snort-([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        r"Snort Version ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [
        ("martin_roesch", "snort"),
        ("snort", "snort"),
        ("sourcefire", "snort"),
    ]
