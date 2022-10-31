# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for jack2

https://www.cvedetails.com/product/73443/Jackaudio-Jack2.html?vendor_id=22111

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Jack2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"jackdmp ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("jackaudio", "jack2")]
