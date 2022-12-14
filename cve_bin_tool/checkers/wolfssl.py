# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wolfssl

https://www.cvedetails.com/product/33078/Wolfssl-Wolfssl.html?vendor_id=15776

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class WolfsslChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"wolfSSL ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("wolfssl", "wolfssl")]
