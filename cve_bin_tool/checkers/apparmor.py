# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for apparmor

https://www.cvedetails.com/product/30362/Ubuntu-Apparmor.html?vendor_id=51
https://www.cvedetails.com/product/36556/Apparmor-Apparmor.html?vendor_id=16268
https://www.cvedetails.com/product/53789/Canonical-Apparmor.html?vendor_id=4781

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ApparmorChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"%s version ([0-9]+\.[0-9]+(\.[0-9]+)?)[A-Za-z:%,/'_ \-\[\]\r\n\t]*apparmor"
    ]
    VENDOR_PRODUCT = [
        ("apparmor", "apparmor"),
        ("canonical", "apparmor"),
        ("ubuntu", "apparmor"),
    ]
