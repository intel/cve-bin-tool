# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for assimp

https://www.cvedetails.com/product/107135/Assimp-Assimp.html?vendor_id=26183

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AssimpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"assimp-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("assimp", "assimp")]
