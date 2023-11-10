# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for terminology

https://www.cvedetails.com/product/60929/Enlightenment-Terminology.html?vendor_id=1065

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TerminologyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nterminology",
        r"terminology ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("enlightenment", "terminology")]
