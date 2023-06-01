# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libmicrohttpd

https://www.cvedetails.com/product/26645/GNU-Libmicrohttpd.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibmicrohttpdChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"MHD-worker[a-zA-Z0-9:%@+ \(\"\-\.\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"
    ]
    VENDOR_PRODUCT = [("gnu", "libmicrohttpd")]
