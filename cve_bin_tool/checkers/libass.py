# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libass

https://www.cvedetails.com/product/36103/Libass-Project-Libass.html?vendor_id=16160

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibassChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)\r?\nlibass"]
    VENDOR_PRODUCT = [("libass_project", "libass")]
