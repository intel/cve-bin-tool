# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for freerdp:

https://www.cvedetails.com/product/45863/Freerdp-Freerdp.html?vendor_id=17919

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FreerdpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"freerdp2-([0-9]+\.[0-9]+\.[0-9]+)",
        r"FreeRDP-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("freerdp", "freerdp")]
