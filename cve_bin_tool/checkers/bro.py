# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bro

https://www.cvedetails.com/product/37247/BRO-BRO.html?vendor_id=16374

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BroChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"bro-([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [("bro", "bro")]
