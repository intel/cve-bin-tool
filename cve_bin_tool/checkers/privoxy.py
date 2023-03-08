# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for privoxy

https://www.cvedetails.com/product/24751/Privoxy-Privoxy.html?vendor_id=12615

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PrivoxyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = ["Privoxy version ([0-9]+\\.[0-9]+\\.[0-9]+)"]
    VENDOR_PRODUCT = [("privoxy", "privoxy")]
