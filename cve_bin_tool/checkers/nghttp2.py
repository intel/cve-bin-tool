# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for nghttp2

https://www.cvedetails.com/product/33064/Nghttp2-Nghttp2.html?vendor_id=15772

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Nghttp2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"nghttp2/([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nnghttp2[-_]",
    ]
    VENDOR_PRODUCT = [("nghttp2", "nghttp2")]
