# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for netdata

https://www.cvedetails.com/product/57777/Netdata-Netdata.html?vendor_id=20255

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class NetdataChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"NETDATA[A-Za-z_=%\-\r\n]*v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("netdata", "netdata")]
