# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for doxygen:

https://www.cvedetails.com/product/55256/Doxygen-Doxygen.html?vendor_id=19902

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DoxygenChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"doxygen-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("doxygen", "doxygen")]
