# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for librsync

https://www.cvedetails.com/product/32538/Librsync-Project-Librsync.html?vendor_id=15685

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibrsyncChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"librsync ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("librsync_project", "librsync")]
