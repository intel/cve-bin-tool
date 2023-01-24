# Copyright (C) 2022 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for spice

https://www.cvedetails.com/product/25789/Spice-Project-Spice.html?vendor_id=12813

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class SpiceChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"SPICE_SERVER_([0-9]+\.[0-9]+\.[0-9]+)\r?\nGLIBC"]
    VENDOR_PRODUCT = [("spice_project", "spice")]
