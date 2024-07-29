# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for bison

https://www.cvedetails.com/product/86839/GNU-Bison.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BisonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"GNU Bison ([0-9]+\.[0-9]+\.[0-9]+)\r?\n"]
    VENDOR_PRODUCT = [("gnu", "bison")]
