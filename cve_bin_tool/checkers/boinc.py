# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for boinc

https://www.cvedetails.com/product/27779/Rom-Walton-Boinc.html?vendor_id=13367
https://www.cvedetails.com/product/63697/Berkeley-Boinc.html?vendor_id=356

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BoincChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"boinc.so.([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nboinc",
    ]
    VENDOR_PRODUCT = [("berkeley", "boinc"), ("rom_walton", "boinc")]
