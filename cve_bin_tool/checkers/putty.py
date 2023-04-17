# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for putty

https://www.cvedetails.com/product/817/Putty-Putty.html?vendor_id=471
https://www.cvedetails.com/product/25776/Simon-Tatham-Putty.html?vendor_id=12807

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PuttyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"putty-([0-9]+\.[0-9]+)",
        r"PuTTY-Release-([0-9]+\.[0-9]+)\r?\n",
    ]
    VENDOR_PRODUCT = [("putty", "putty"), ("simon_tatham", "putty")]
