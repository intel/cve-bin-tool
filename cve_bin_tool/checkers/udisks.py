# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for udisks

https://www.cvedetails.com/product/19087/Freedesktop-Udisks.html?vendor_id=7971
https://www.cvedetails.com/product/62239/Udisks-Project-Udisks.html?vendor_id=21042

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class UdisksChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"udisks2-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("freedesktop", "udisks"), ("udisks_project", "udisks")]
