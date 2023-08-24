# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dav1d:

https://www.cvedetails.com/product/139658/Videolan-Dav1d.html?vendor_id=5842

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Dav1DChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9 '.()%,:\r\n\/\-]*dav1d"]
    VENDOR_PRODUCT = [("videolan", "dav1d")]
