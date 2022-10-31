# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for neon

https://www.cvedetails.com/product/9932/Neon-Neon.html?vendor_id=2119
https://www.cvedetails.com/product/14835/Webdav-Neon.html?vendor_id=8471

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NeonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"neon ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("neon", "neon"), ("webdav", "neon")]
