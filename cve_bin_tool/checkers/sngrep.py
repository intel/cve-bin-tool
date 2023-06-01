# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sngrep

https://www.cvedetails.com/product/139725/Irontec-Sngrep.html?vendor_id=29812

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SngrepChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"sngrep\r?\n([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("irontec", "sngrep")]
