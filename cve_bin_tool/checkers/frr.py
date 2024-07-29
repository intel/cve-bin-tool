# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for frr

https://www.cvedetails.com/product/41416/Frrouting-Frrouting.html?vendor_id=17227
https://www.cvedetails.com/product/86226/Linuxfoundation-Free-Range-Routing.html?vendor_id=11448

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FrrChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\n(?:babeld|bfdd|eigrpd|fabricd|isisd|ldpd|nhrpd|ospfd|ospf6d|pathd|pbrd|pimd|ripd|ripngd|staticd|vrrpd|watchfrr|zebra) daemon",
        r"FRR \(version ([0-9]+\.[0-9]+(\.[0-9]+)?)",
    ]
    VENDOR_PRODUCT = [
        ("frrouting", "frrouting"),
        ("linuxfoundation", "free_range_routing"),
    ]
