# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zabbix

https://www.cvedetails.com/product/9588/Zabbix-Zabbix.html?vendor_id=5667

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZabbixChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Zabbix ([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nZabbix",
    ]
    VENDOR_PRODUCT = [("zabbix", "zabbix")]
