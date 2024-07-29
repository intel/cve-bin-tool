# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libheif

https://www.cvedetails.com/product/53699/Struktur-Libheif.html?vendor_id=19782

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibheifChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9/_ \r\n]*[h|H]eif"]
    VENDOR_PRODUCT = [("struktur", "libheif")]
