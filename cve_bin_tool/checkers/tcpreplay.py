# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for tcpreplay

https://www.cvedetails.com/product/111655/Broadcom-Tcpreplay.html?vendor_id=5420

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TcpreplayChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z %$/\.\:\(\)\r?\n]*tcp(?:prep|replay|rewrite) version"
    ]
    VENDOR_PRODUCT = [("broadcom", "tcpreplay")]
