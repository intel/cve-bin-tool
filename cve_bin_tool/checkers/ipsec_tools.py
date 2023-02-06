# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ipsec-tools:

https://www.cvedetails.com/product/3996/Ipsec-tools-Ipsec-tools.html?vendor_id=2282

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IpsecToolsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ipsec-tools ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("ipsec-tools", "ipsec-tools")]
