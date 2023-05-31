# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cpio

https://www.cvedetails.com/product/5080/GNU-Cpio.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CpioChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+)\r?\nGNU cpio"]
    VENDOR_PRODUCT = [("gnu", "cpio")]
