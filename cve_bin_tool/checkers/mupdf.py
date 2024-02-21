# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for mupdf

https://www.cvedetails.com/product/20840/Artifex-Mupdf.html?vendor_id=10846

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MupdfChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"mupdf[A-Za-z '/:%\-\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("artifex", "mupdf")]
