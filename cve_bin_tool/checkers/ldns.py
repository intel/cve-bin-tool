# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ldns

https://www.cvedetails.com/product/17169/Nlnetlabs-Ldns.html?vendor_id=9613

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LdnsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ldns[a-zA-Z0-9_*\)\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("nlnetlabs", "ldns")]
