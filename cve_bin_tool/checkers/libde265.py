# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libde265

https://www.cvedetails.com/product/107590/Struktur-Libde265.html?vendor_id=19782

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Libde265Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0-9/!=_,:<>. \[\]\(\)\-\r\n]*de265"
    ]
    VENDOR_PRODUCT = [("struktur", "libde265")]
