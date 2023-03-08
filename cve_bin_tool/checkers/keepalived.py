# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for keepalived

https://www.cvedetails.com/product/20859/Keepalived-Keepalived.html?vendor_id=11406

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class KeepalivedChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["Keepalived v([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("keepalived", "keepalived")]
