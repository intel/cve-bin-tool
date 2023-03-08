# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for davfs2

https://www.cvedetails.com/product/5417/Davfs2-Davfs2.html?vendor_id=3075
https://www.cvedetails.com/product/26180/Werner-Baumann-Davfs2.html?vendor_id=12878

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Davfs2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"davfs2 ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("davfs2", "davfs2"), ("werner_baumann", "davfs2")]
