# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for axel

https://www.cvedetails.com/product/4969/Axel-Axel.html?vendor_id=2842
https://www.cvedetails.com/product/87416/Axel-Project-Axel.html?vendor_id=23577

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AxelChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Axel/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("axel", "axel"), ("axel_project", "axel")]
