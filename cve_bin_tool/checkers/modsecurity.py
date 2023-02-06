# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for modsecurity

https://www.cvedetails.com/product/62133/Trustwave-Modsecurity.html?vendor_id=11396

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ModsecurityChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ModSecurity v([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("trustwave", "modsecurity")]
