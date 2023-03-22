# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pcre

https://www.cvedetails.com/product/5715/Pcre-Pcre.html?vendor_id=3265

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PcreChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"argument is not a compiled regular expression[a-z0-9 :\(\)\r\n]*([0-9]+\.[0-9]+) [0-9]+\-[0-9]+\-[0-9]+\r?\n",
        r"([0-9]+\.[0-9]+) [0-9]+\-[0-9]+\-[0-9]+\r?\nargument is not a compiled regular expression",
        r"([0-9]+\.[0-9]+) [0-9]+\-[0-9]+\-[0-9]+\r?\n !\"#\$%&'\(\)\*\+,-\./0123456789:;<=>\?@abcdefghijklmnopqrstuvwxyz\[\\\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}~",
    ]
    VENDOR_PRODUCT = [("pcre", "pcre")]
