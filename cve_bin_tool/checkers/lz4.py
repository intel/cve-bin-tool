# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lz4:

https://www.cvedetails.com/product/28069/Yann-Collet-LZ4.html?vendor_id=13512
https://www.cvedetails.com/product/76615/Lz4-Project-LZ4.html?vendor_id=22424

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Lz4Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"lz4-([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nUnspecified error code\r?\nOK_NoError",
    ]
    VENDOR_PRODUCT = [("lz4_project", "lz4"), ("yann_collet", "lz4")]
