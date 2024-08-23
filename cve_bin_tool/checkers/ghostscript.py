# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ghostscript

https://www.cvedetails.com/product/12939/Ghostscript-Ghostscript.html?vendor_id=7640
https://www.cvedetails.com/product/36469/Artifex-Ghostscript.html?vendor_id=10846

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GhostscriptChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"ghostscript/([0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n[a-z:/]*ghostscript",
    ]
    VENDOR_PRODUCT = [("artifex", "ghostscript"), ("ghostscript", "ghostscript")]
