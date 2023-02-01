# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for sslh

https://www.cvedetails.com/product/126792/Sslh-Project-Sslh.html?vendor_id=29001

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SslhChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"sslh ([0-9]+\.[0-9a-z]+)",
        r"sslh v([0-9]+\.[0-9a-z]+)",
        r"sslh-([0-9]+\.[0-9a-z]+)",
    ]
    VENDOR_PRODUCT = [("sslh_project", "sslh")]
