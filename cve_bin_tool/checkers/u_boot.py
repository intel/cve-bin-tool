# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for u-boot

https://www.cvedetails.com/product/48033/Denx-U-boot.html?vendor_id=18843

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class UBootChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"U-Boot ([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("denx", "u-boot")]
