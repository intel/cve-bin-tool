# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for iwd

https://www.cvedetails.com/product/88024/Intel-Inet-Wireless-Daemon.html?vendor_id=238

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IwdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)\r?\nIWD version %s",
        r"iwctl version ([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("intel", "inet_wireless_daemon")]
