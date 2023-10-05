# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mpg123

https://www.cvedetails.com/product/3045/Mpg123-Mpg123.html?vendor_id=1781

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Mpg123Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"mpg123\r?\n([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("mpg123", "mpg123")]
