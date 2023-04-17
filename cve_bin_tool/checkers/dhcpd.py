# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dhcpd (ISC DHCP server)

https://www.cvedetails.com/product/2017/ISC-Dhcpd.html?vendor_id=64
https://www.cvedetails.com/product/17706/ISC-Dhcp.html?vendor_id=64

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DhcpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"\r?\ndhcpd\.c[a-zA-Z0-9 \'%-\[\]{}<>#%|\.:\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 \'%-\[\]{}<>#%|\.:\r\n]*dhcpd\.c\r?\n",
    ]
    VENDOR_PRODUCT = [("isc", "dhcp"), ("isc", "dhcpd")]
