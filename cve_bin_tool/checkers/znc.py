# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for znc

https://www.cvedetails.com/product/16944/ZNC-ZNC.html?vendor_id=9558

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZncChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"znc-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n[a-zA-Z,: \[]*\r?\n[\./]*[zZ][nN][cC]",
    ]
    VENDOR_PRODUCT = [("znc", "znc")]
