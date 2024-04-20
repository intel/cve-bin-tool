# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libuv

https://www.cvedetails.com/product/31692/Libuv-Project-Libuv.html?vendor_id=15402
https://www.cvedetails.com/product/64484/Libuv-Libuv.html?vendor_id=21357

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibuvChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"(?:\n|lib)uv[a-z-_\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z/_%: \-\r\n]*\r?\nUV",
    ]
    VENDOR_PRODUCT = [("libuv_project", "libuv"), ("libuv", "libuv")]
