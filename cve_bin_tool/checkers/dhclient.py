# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dhcp-client (ISC DHCP client)

https://www.cvedetails.com/product/610/ISC-Dhcp-Client.html?vendor_id=64
https://www.cvedetails.com/product/17706/ISC-Dhcp.html?vendor_id=64

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DhclientChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = [r"dhclient"]
    VERSION_PATTERNS = [
        r"dhclient\.c[a-zA-Z0-9 \'%-\[\]{}<>#%|\.:\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 \'%-\[\]{}<>#%|\.:\r\n]*dhclient\.c",
    ]
    VENDOR_PRODUCT = [("isc", "dhcp"), ("isc", "dhcp_client")]
