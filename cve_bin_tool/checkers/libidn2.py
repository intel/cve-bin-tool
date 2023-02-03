# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libidn2

https://www.cvedetails.com/product/65468/GNU-Libidn2.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Libidn2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"libidn2[a-z0-9\.]*-([0-9]+\.[0-9]+\.[0-9]+)",
        r"Simon Josefsson[a-zA-Z ,]*\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nCopyright \(C\) [0-9-]*  Simon Josefsson",
    ]
    VENDOR_PRODUCT = [("gnu", "libidn2")]
