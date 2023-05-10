# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for pango

https://www.cvedetails.com/product/17354/Pango-Pango.html?vendor_id=9705
https://www.cvedetails.com/product/98217/Gnome-Pango.html?vendor_id=283

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PangoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n/etc/pango",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nPango version",
    ]
    VENDOR_PRODUCT = [("gnome", "pango"), ("pango", "pango")]
