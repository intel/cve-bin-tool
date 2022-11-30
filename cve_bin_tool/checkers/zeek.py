# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zeek

https://www.cvedetails.com/product/57109/Zeek-Zeek.html?vendor_id=20112

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZeekChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"zeek-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("zeek", "zeek")]
