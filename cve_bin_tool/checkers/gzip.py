# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gzip

https://www.cvedetails.com/product/1670/GNU-Gzip.html?vendor_id=72
https://www.cvedetails.com/product/8772/Gzip-Gzip.html?vendor_id=5134

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GzipChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"file size changed while zipping\r?\n([0-9]+\.[0-9]+)",
        r"Written by Jean-loup Gailly.[a-zA-Z0-9:%,' \-\.\r\n]*\r?\n([0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gnu", "gzip"), ("gzip", "gzip")]
