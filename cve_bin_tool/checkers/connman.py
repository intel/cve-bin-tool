# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for connman

https://www.cvedetails.com/product/22328/Connman-Connman.html?vendor_id=11940
https://www.cvedetails.com/product/63425/Intel-Connman.html?vendor_id=238

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ConnmanChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+)\r?\nGWeb/%s"]
    VENDOR_PRODUCT = [("connman", "connman"), ("intel", "connman")]
