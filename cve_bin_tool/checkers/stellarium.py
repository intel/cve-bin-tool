# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for stellarium

https://www.cvedetails.com/product/136702/Stellarium-Stellarium.html?vendor_id=30039

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class StellariumChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"stellarium-([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("stellarium", "stellarium")]
