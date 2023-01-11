# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zstandard:

https://www.cvedetails.com/product/57378/Facebook-Zstandard.html?vendor_id=7758

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZstandardChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Frame requires too much memory for decoding[a-zA-Z :(#$'/\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
        r"\r?\n([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9 -|<>/._=%:(#$'/\[\]\r\n]*Frame requires too much memory for decoding",
    ]
    VENDOR_PRODUCT = [("facebook", "zstandard")]
