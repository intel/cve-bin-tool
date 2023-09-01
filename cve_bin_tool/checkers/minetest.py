# Copyright (C) 2023 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for minetest

https://www.cvedetails.com/product/108535/Minetest-Minetest.html?vendor_id=26371

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class MinetestChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"minetest-([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("minetest", "minetest")]
