# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for rdesktop

https://www.cvedetails.com/product/13976/Rdesktop-Rdesktop.html?vendor_id=8065

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RdesktopChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"rdesktop: A Remote Desktop Protocol client.\r?\nVersion ([0-9]+\.[0-9]+\.[0-9]+)"
    ]
    VENDOR_PRODUCT = [("rdesktop", "rdesktop")]
