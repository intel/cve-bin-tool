# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for i2pd

https://www.cvedetails.com/product/42076/I2pd-I2pd.html?vendor_id=17310

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class I2PdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        "i2pd v\\r?\\n([0-9]+\\.[0-9]+\\.[0-9]+)",
        "i2pd\\r?\\n([0-9]+\\.[0-9]+\\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("i2pd", "i2pd")]
