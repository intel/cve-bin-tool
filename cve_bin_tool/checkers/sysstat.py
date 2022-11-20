# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sysstat:

https://www.cvedetails.com/product/3570/Redhat-Sysstat.html?vendor_id=25
https://www.cvedetails.com/product/3571/Sysstat-Sysstat.html?vendor_id=2093
https://www.cvedetails.com/product/51283/Sysstat-Project-Sysstat.html?vendor_id=19496

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SysstatChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"sysstat version %s\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nsysstat version %s",
    ]
    VENDOR_PRODUCT = [
        ("redhat", "sysstat"),
        ("sysstat", "sysstat"),
        ("sysstat_project", "sysstat"),
    ]
