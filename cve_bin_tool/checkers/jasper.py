# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for jasper

https://www.cvedetails.com/product/15057/Jasper-Project-Jasper.html?vendor_id=8582

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JasperChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-z%: \[\]\-\r\n]*libjasper",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nJasPer",
    ]
    VENDOR_PRODUCT = [("jasper_project", "jasper")]
