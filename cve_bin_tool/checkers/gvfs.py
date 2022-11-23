# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gvfs

https://www.cvedetails.com/product/55291/Gnome-Gvfs.html?vendor_id=283

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GvfsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"gvfs ([0-9]+\.[0-9]+\.[0-9]+)",
        r"gvfs/([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnome", "gvfs")]
