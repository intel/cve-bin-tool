# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for socat

https://www.cvedetails.com/product/4156/Socat-Socat.html?vendor_id=2377
https://www.cvedetails.com/product/19994/Dest-unreach-Socat.html?vendor_id=11111

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SocatChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"socat[a-zA-Z0-9:. \-\r\n]*\r?\n([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"
    ]
    VENDOR_PRODUCT = [("dest-unreach", "socat"), ("socat", "socat")]
