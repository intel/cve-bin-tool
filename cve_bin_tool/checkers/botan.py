# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for botan

https://www.cvedetails.com/product/33791/Botan-Project-Botan.html?vendor_id=15841

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BotanChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Botan ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("botan_project", "botan")]
