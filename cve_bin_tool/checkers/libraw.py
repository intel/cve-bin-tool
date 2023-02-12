# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libraw

https://www.cvedetails.com/product/25761/Libraw-Libraw.html?vendor_id=12800

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibrawChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)-Release[a-zA-z \r\n]*Reading RAW",
        r"[lL]ibraw[a-zA-z ,/\r\n]*([0-9]+\.[0-9]+\.[0-9]+)-Release",
    ]
    VENDOR_PRODUCT = [("libraw", "libraw")]
