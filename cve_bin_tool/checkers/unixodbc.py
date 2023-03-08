# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for unixodbc

https://www.cvedetails.com/product/23028/Unixodbc-Unixodbc.html?vendor_id=12200

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class UnixodbcChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"unixODBC ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("unixodbc", "unixodbc")]
