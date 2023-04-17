# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for apcupsd

https://www.cvedetails.com/product/1160/APC-Apcupsd.html?vendor_id=625
https://www.cvedetails.com/product/55361/Apcupsd-Apcupsd.html?vendor_id=16632

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ApcupsdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["apcupsd ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("apc", "apcupsd"), ("apcupsd", "apcupsd")]
