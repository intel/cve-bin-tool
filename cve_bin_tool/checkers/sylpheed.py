# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sylpheed

https://www.cvedetails.com/product/3149/Sylpheed-Sylpheed.html?vendor_id=1716
https://www.cvedetails.com/product/42176/Sylpheed-Project-Sylpheed.html?vendor_id=17369

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SylpheedChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Sylpheed ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("sylpheed", "sylpheed"), ("sylpheed_project", "sylpheed")]
