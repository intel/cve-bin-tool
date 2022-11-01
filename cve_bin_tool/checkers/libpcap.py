# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libpcap

https://www.cvedetails.com/product/61186/Tcpdump-Libpcap.html?vendor_id=6197

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibpcapChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libpcap version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("tcpdump", "libpcap")]
