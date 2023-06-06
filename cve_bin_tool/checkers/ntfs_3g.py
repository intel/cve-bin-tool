# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ntfs-3g

https://www.cvedetails.com/product/45193/Tuxera-Ntfs-3g.html?vendor_id=17875

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Ntfs3GChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"ntfs-3g[0-9a-zA-Z/%. \r\n]*\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nntfs-3g",
    ]
    VENDOR_PRODUCT = [("tuxera", "ntfs-3g")]
