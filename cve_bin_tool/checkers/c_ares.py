# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for c-ares

https://www.cvedetails.com/product/11384/Daniel-Stenberg-C-ares.html?vendor_id=613
https://www.cvedetails.com/product/34754/C-ares-Project-C-ares.html?vendor_id=15926
https://www.cvedetails.com/product/160076/C-ares-C-ares.html?vendor_id=32666

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CAresChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"c-ares-([0-9]+\.[0-9]+\.[0-9]+)",
        r"c-ares library initialization[A-Za-z \.\r\n]+\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [
        ("c-ares", "c-ares"),
        ("c-ares_project", "c-ares"),
        ("daniel_stenberg", "c-ares"),
    ]
