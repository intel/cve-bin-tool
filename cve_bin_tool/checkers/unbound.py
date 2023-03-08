# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for unbound

https://www.cvedetails.com/product/18208/Unbound-Unbound.html?vendor_id=10197
https://www.cvedetails.com/product/20882/Nlnetlabs-Unbound.html?vendor_id=9613

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class UnboundChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"unbound ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("nlnetlabs", "unbound"), ("unbound", "unbound")]
