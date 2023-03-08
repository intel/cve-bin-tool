# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libgit2

https://www.cvedetails.com/product/35762/Libgit2-Project-Libgit2.html?vendor_id=16066
https://www.cvedetails.com/product/61358/Libgit2-Libgit2.html?vendor_id=20885

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Libgit2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libgit2 ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libgit2", "libgit2"), ("libgit2_project", "libgit2")]
