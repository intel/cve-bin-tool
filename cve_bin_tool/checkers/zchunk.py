# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zchunk

https://www.cvedetails.com/product/163243/Zchunk-Zchunk.html?vendor_id=33326

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZchunkChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"zchunk ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("zchunk", "zchunk")]
