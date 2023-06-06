# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libtasn1

https://www.cvedetails.com/product/3620/Free-Software-Foundation-Inc.-Libtasn1.html?vendor_id=2125
https://www.cvedetails.com/product/22173/GNU-Libtasn1.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Libtasn1Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ASSIGNMENT,[a-zA-Z:\r\n]*\r?\n([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [
        ("free_software_foundation_inc.", "libtasn1"),
        ("gnu", "libtasn1"),
    ]
