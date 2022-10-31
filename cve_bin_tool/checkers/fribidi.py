# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for fribidi

https://www.cvedetails.com/product/75615/GNU-Fribidi.html?vendor_id=72

"""
from cve_bin_tool.checkers import Checker


class FribidiChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = []
    VERSION_PATTERNS = [
        r"fribidi ([0-9]+\.[0-9]+\.[0-9]+)",
        r"\(GNU FriBidi\) ([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "fribidi")]
