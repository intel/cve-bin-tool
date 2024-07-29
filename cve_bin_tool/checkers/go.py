# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for go

https://www.cvedetails.com/product/29205/Golang-GO.html?vendor_id=14185

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"go([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("golang", "go")]
