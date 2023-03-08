# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for xscreensaver

https://www.cvedetails.com/product/3177/Xscreensaver-Xscreensaver.html?vendor_id=1861
https://www.cvedetails.com/product/32618/Xscreensaver-Project-Xscreensaver.html?vendor_id=15709

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class XscreensaverChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"[xX][sS]creen[sS]aver ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("xscreensaver", "xscreensaver"),
        ("xscreensaver_project", "xscreensaver"),
    ]
