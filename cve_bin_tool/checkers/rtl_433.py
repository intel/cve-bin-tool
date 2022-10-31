# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rtl_433

https://www.cvedetails.com/product/110856/Rtl-433-Project-Rtl-433.html?vendor_id=26553

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Rtl433Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"rtl[-_]433-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("rtl_433_project", "rtl_433")]
