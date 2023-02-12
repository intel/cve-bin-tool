# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libmatroska

https://www.cvedetails.com/product/33122/Matroska-Libmatroska.html?vendor_id=7864

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibmatroskaChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libmatroska-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("matroska", "libmatroska")]
