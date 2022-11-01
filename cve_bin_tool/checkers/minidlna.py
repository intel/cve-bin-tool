# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for minidlna

https://www.cvedetails.com/product/63590/Minidlna-Project-Minidlna.html?vendor_id=21154
https://www.cvedetails.com/product/63524/Readymedia-Project-Readymedia.html?vendor_id=21140

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MinidlnaChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"MiniDLNA ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("minidlna_project", "minidlna"),
        ("readymedia_project", "readymedia"),
    ]
