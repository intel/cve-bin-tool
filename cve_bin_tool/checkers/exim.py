# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for exim

https://www.cvedetails.com/product/153/University-Of-Cambridge-Exim.html?vendor_id=92
https://www.cvedetails.com/product/19563/Exim-Exim.html?vendor_id=10919

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class EximChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"exim/([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\n<<eximversion>>",
    ]
    VENDOR_PRODUCT = [("exim", "exim"), ("university_of_cambridge", "exim")]
