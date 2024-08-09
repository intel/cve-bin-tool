# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ttyd

https://www.cvedetails.com/product/135838/Ttyd-Project-Ttyd.html?vendor_id=29796

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class TtydChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[a-z\r\n]*ttyd"]
    VENDOR_PRODUCT = [("ttyd_project", "ttyd")]
