# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bwm-ng:

https://www.cvedetails.com/product/113242/Bwm-ng-Project-Bwm-ng.html?vendor_id=26951

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BwmNgChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"bwm-ng v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("bwm-ng_project", "bwm-ng")]
