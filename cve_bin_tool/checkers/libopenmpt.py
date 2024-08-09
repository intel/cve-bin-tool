# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libopenmpt

https://www.cvedetails.com/product/38959/Openmpt-Libopenmpt.html?vendor_id=16722

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibopenmptChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libopenmpt-([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openmpt", "libopenmpt")]
