# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for harfbuzz

https://www.cvedetails.com/product/33083/Harfbuzz-Project-Harfbuzz.html?vendor_id=15778

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class HarfbuzzChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"HB_OPTIONS\r?\nuniscribe-bug-compatible\r?\ninvalid\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nHarfBuzz",
    ]
    VENDOR_PRODUCT = [("harfbuzz_project", "harfbuzz")]
