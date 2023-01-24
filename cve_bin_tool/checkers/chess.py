# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for chess

https://www.cvedetails.com/product/1867/GNU-Chess.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ChessChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Chess ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "chess")]
