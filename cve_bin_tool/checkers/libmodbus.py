# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libmodbus

https://www.cvedetails.com/product/57330/Libmodbus-Libmodbus.html?vendor_id=20193

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibmodbusChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"LMB([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libmodbus", "libmodbus")]
