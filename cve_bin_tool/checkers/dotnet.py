# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for system.net.http:
https://www.cvedetails.com/version-list/26/39158/1/Microsoft-System.net.http.html
https://www.cvedetails.com/version-list/0/80849/1/?q=.net

"""

from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DotnetChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS: list[str] = [
        r"dotnet-v([0-9]+\.[0-9]+\.[0-9]{1,2})",
    ]
    VENDOR_PRODUCT: list[tuple[str, str]] = [
        ("microsoft", ".net"),
        ("microsoft", "system.net.http"),
    ]
