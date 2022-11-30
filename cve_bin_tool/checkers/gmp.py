# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gmp

https://www.cvedetails.com/product/103812/Gmplib-GMP.html?vendor_id=25912

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GmpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"gmp[a-z0-9\.]*-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n0123456789abcdefghijklmnopqrstuvwxyz",
    ]
    VENDOR_PRODUCT = [("gmplib", "gmp")]
