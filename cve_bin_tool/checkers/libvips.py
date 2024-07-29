# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libvips

https://www.cvedetails.com/product/160947/Libvips-Libvips.html?vendor_id=32880

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibvipsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9./%: \-\(\)\r\n]*libvips"]
    VENDOR_PRODUCT = [("libvips", "libvips")]
