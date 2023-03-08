# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libconfuse

https://www.cvedetails.com/product/48849/Libconfuse-Project-Libconfuse.html?vendor_id=19058

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibconfuseChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libConfuse ([0-9]+\.[0-9]+\.?[0-9]*)"]
    VENDOR_PRODUCT = [("libconfuse_project", "libconfuse")]
