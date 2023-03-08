# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for glib

https://www.cvedetails.com/product/16275/Gnome-Glib.html?vendor_id=283

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GlibChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"GDBus ([0-9]+\.[0-9]+\.[0-9]+)",
        r"glib-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnome", "glib")]
