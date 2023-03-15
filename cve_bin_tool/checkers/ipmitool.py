# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ipmitool:

https://www.cvedetails.com/product/92986/Ipmitool-Project-Ipmitool.html?vendor_id=24402

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IpmitoolChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 !:,\.<>\[\]\(\)=/%\-\r\n]*IPMI[_v]"
    ]
    VENDOR_PRODUCT = [("ipmitool_project", "ipmitool")]
