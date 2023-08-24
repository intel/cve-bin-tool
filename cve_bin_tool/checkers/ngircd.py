# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ngircd

https://www.cvedetails.com/product/4749/Ngircd-Ngircd.html?vendor_id=2709
https://www.cvedetails.com/product/26242/Barton-Ngircd.html?vendor_id=12890

Note: Unfortunately, we can't catch some ngircd version which are on two digits (e.g. 25)
because cve-bin-tool only extracts strings which have more than 3 characters

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NgircdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)\r?\n(?:ngIRCd|/ngircd)",
        r"ngIRCd\r?\n%s %s-%s\r?\n([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("barton", "ngircd"), ("ngircd", "ngircd")]
