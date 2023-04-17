# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cvs

https://www.cvedetails.com/product/758/CVS-CVS.html?vendor_id=442
https://www.cvedetails.com/product/20192/Nongnu-CVS.html?vendor_id=6788
https://www.cvedetails.com/product/40040/GNU-CVS.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CvsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"CVS\) ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("cvs", "cvs"), ("gnu", "cvs"), ("nongnu", "cvs")]
