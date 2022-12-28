# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for jhead

https://www.cvedetails.com/product/15156/Sentex-Jhead.html?vendor_id=8626
https://www.cvedetails.com/product/43523/Jhead-Project-Jhead.html?vendor_id=17612

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JheadChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Jhead version: ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("jhead_project", "jhead"), ("sentex", "jhead")]
