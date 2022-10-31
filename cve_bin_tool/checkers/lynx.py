# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for lynx

https://www.cvedetails.com/product/354/University-Of-Kansas-Lynx.html?vendor_id=205
https://www.cvedetails.com/product/9869/Lynx-Lynx.html?vendor_id=5836
https://www.cvedetails.com/product/41503/Lynx-Project-Lynx.html?vendor_id=17248

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LynxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9a-z]+\.?[0-9]*)\r?\nLynx",
        r"https://lynx.invisible-island.net/\r?\n([0-9]+\.[0-9]+\.[0-9a-z]+\.?[0-9]*)",
    ]
    VENDOR_PRODUCT = [
        ("lynx", "lynx"),
        ("lynx_project", "lynx"),
        ("university_of_kansas", "lynx"),
    ]
