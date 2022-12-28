# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for chrony

https://www.cvedetails.com/product/18821/Tuxfamily-Chrony.html?vendor_id=10533
https://www.cvedetails.com/product/64144/Chrony-Project-Chrony.html?vendor_id=21263

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ChronyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+)\r?\nchrony",
        r"chrony\r?\n([0-9]+\.[0-9]+)",
        r"\(chrony\) version %s\r?\n([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("chrony_project", "chrony"), ("tuxfamily", "chrony")]
