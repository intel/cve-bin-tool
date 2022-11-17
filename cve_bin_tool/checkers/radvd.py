# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for router_advertisement_daemon:

https://www.cvedetails.com/product/27101/Litech-Router-Advertisement-Daemon.html?vendor_id=13131

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RadvdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\nVersion: %s\r?\nCompiled in settings:\r?\n",
        r"Version: %s\r?\n([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\nCompiled in settings:\r?\n",
    ]
    VENDOR_PRODUCT = [("litech", "router_advertisement_daemon")]
