# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dhcpcd

https://www.cvedetails.com/product/2742/Phystech-Dhcpcd.html?vendor_id=1590
https://www.cvedetails.com/product/20668/Roy-Marples-Dhcpcd.html?vendor_id=11378
https://www.cvedetails.com/product/28439/Dhcpcd-Project-Dhcpcd.html?vendor_id=13642

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DhcpcdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"dhcpcd ([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [
        ("phystech", "dhcpcd"),
        ("roy_marples", "dhcpcd"),
        ("dhcpcd_project", "dhcpcd"),
    ]
