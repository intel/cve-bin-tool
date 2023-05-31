# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pixman

https://www.cvedetails.com/product/24853/Pixman-Pixman.html?vendor_id=12651

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PixmanChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n[\./]*pixman",
        r"pixman[a-zA-Z=> \-\.\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("pixman", "pixman")]
